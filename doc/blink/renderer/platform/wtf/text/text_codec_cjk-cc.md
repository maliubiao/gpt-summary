Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional breakdown of the `text_codec_cjk.cc` file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), and common user/programming errors.

2. **Initial Skim for Keywords and Structure:**  Read through the code quickly, looking for:
    * **File Path:** `blink/renderer/platform/wtf/text/text_codec_cjk.cc` indicates this is related to text encoding within the Blink rendering engine. "CJK" strongly suggests handling Chinese, Japanese, and Korean character sets.
    * **Copyright:**  Apple Inc., 2020. This tells us who created it and roughly when.
    * **Includes:**  Headers like `<utility>`, `base/feature_list.h`, `third_party/blink/public/common/features.h`, `third_party/blink/renderer/platform/wtf/text/...` provide clues about dependencies and the purpose of the code. The `wtf/text` namespace is particularly relevant.
    * **Namespaces:** The code is within the `WTF` namespace, a common namespace in Blink.
    * **Class Names:** `TextCodecCJK`, `Decoder`, `EucJpDecoder`, `Iso2022JpDecoder`, etc., are key components.
    * **Constants:**  `kCanonicalNameEucJp`, `kCanonicalNameShiftJis`, etc., define supported encoding names.
    * **Functions:** `Decode`, `Encode`, `ParseByte`, `Finalize`, `RegisterEncodingNames`, `RegisterCodecs`, `Create`, `IsSupported`.
    * **Data Structures:** `Vector<uint8_t>`, `StringBuilder`, `std::array`.
    * **Comments:**  Look for `// https://encoding.spec.whatwg.org/...` – these point to the WHATWG Encoding Standard, the authority on web encoding.

3. **Identify Core Functionality - Encoding and Decoding:** The presence of `Encode` and `Decode` functions, along with different decoder classes (e.g., `EucJpDecoder`), clearly points to the file's primary purpose: converting between byte sequences and Unicode strings for various CJK encodings.

4. **Break Down the `TextCodecCJK` Class:**
    * **Constructor:** Takes an `Encoding` enum, suggesting it's a base class for different CJK encoding implementations.
    * **`RegisterEncodingNames`:**  This function registers the canonical names and aliases for each supported encoding. This is important for web browsers to identify encodings correctly.
    * **`RegisterCodecs`:** Registers the codec with the system, making it available for use.
    * **`Create`:** A factory method to create specific `TextCodecCJK` instances based on the encoding name.
    * **`Decode` (the main one):**  Takes byte data, a flush behavior, an error flag, and uses a specific decoder instance to perform the actual decoding.
    * **`EncodeCommon`:**  A central function that calls the specific encoding functions (e.g., `EncodeEucJp`).
    * **`Encode` (overloads):**  Provides convenience methods for encoding from different character types (`UChar`, `LChar`).
    * **`IsSupported`:** Checks if a given encoding name is supported.

5. **Analyze the `Decoder` Class:**
    * **Virtual Interface:** The `Decoder` class is abstract with virtual `Decode`, `ParseByte`, and `Finalize` methods. This allows for polymorphism, where different decoders implement the decoding logic specific to their encoding.
    * **State Management:**  The `lead_` and `prepended_byte_` members suggest that some decoders need to keep track of state between bytes.

6. **Examine Individual Decoder/Encoder Implementations:** Look at the specific logic within classes like `EucJpDecoder`, `Iso2022JpEncoder`, etc. Note how they handle:
    * **ASCII characters:** Often passed through directly.
    * **Multi-byte sequences:** How they identify and process multi-byte characters.
    * **Escape sequences:**  Especially relevant for `Iso2022Jp`.
    * **Error handling:**  Setting the `saw_error` flag and potentially inserting replacement characters.
    * **Specific encoding rules:** The comments referencing the WHATWG Encoding Standard are invaluable here.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The `<meta charset="...">` tag in HTML specifies the encoding of the document. This code is directly responsible for interpreting that encoding. Incorrect encoding leads to mojibake (garbled text).
    * **JavaScript:**  JavaScript's `TextDecoder` API uses the underlying browser encoding support, which includes this code. Fetching data with an incorrect encoding and then trying to decode it in JavaScript will fail.
    * **CSS:** While CSS itself doesn't directly involve byte-to-Unicode conversion, the text within HTML elements (styled by CSS) relies on correct encoding. If the HTML is mis-encoded, the CSS styling will be applied to the wrong characters.

8. **Logical Reasoning (Input/Output Examples):**  Think about simple cases for each encoding. For example, encoding an ASCII character or a common CJK character. Consider edge cases like invalid byte sequences. The examples provided in the original good answer are excellent for this.

9. **Common Errors:** Consider how developers or users might misuse encodings:
    * **Mismatch between declared encoding and actual encoding:**  The most common problem.
    * **Incorrect server configuration:**  The server might send the wrong `Content-Type` header, leading the browser to misinterpret the encoding.
    * **Manually setting the wrong encoding in the browser:**  Users can sometimes override the detected encoding.
    * **Copying and pasting text between different encodings:** This can introduce encoding issues.

10. **Structure the Answer:** Organize the findings into logical sections:  Core Functionality, Relationship to Web Technologies, Logical Reasoning Examples, Common Errors. Use clear and concise language.

11. **Refine and Review:** Read through the answer to ensure accuracy and completeness. Check for any jargon that needs explanation. Ensure the examples are clear and easy to understand. Make sure the connection between the C++ code and the web technologies is explicit.

Self-Correction/Refinement During the Process:

* **Initial thought:** "This just handles text encoding."  **Refinement:**  "It handles *specific* CJK encodings and needs to adhere to the WHATWG standard for web compatibility."
* **Initial thought:** "How does this relate to JavaScript?" **Refinement:** "Through the `TextDecoder` API. The browser's encoding support is the foundation for JavaScript's text manipulation."
* **Realizing the importance of the WHATWG standard:**  Constantly referring to the specification helps understand the *why* behind certain implementation choices.

By following this structured approach, combining code analysis with understanding of web standards and common error scenarios, we can effectively analyze and explain the functionality of a complex piece of code like `text_codec_cjk.cc`.
这个文件 `blink/renderer/platform/wtf/text/text_codec_cjk.cc` 是 Chromium Blink 引擎中负责处理 **CJK (Chinese, Japanese, Korean)** 字符编码的编解码器。它的主要功能是将字节流解码成 Unicode 字符串，以及将 Unicode 字符串编码成特定 CJK 编码的字节流。

**具体功能包括：**

1. **支持多种 CJK 字符编码：**
   - EUC-JP (用于日语)
   - Shift_JIS (用于日语)
   - EUC-KR (用于韩语)
   - ISO-2022-JP (用于日语)
   - GBK (用于简体中文)
   - GB18030 (用于简体中文)

2. **解码 (Decoding)：**
   - 将以上列出的各种 CJK 编码的字节流转换成 Unicode 字符串。
   - 实现了针对每种编码的特定解码逻辑，处理单字节、双字节或更多字节的字符。
   - 能够处理不完整的字节序列和错误的字节序列，通常会使用替换字符 (�) 来表示无法解码的部分。
   - 提供 `FlushBehavior` 参数来控制是否处理缓冲区中剩余的字节。

3. **编码 (Encoding)：**
   - 将 Unicode 字符串转换成以上列出的各种 CJK 编码的字节流。
   - 实现了针对每种编码的特定编码逻辑。
   - 提供 `UnencodableHandling` 参数来控制如何处理无法在目标编码中表示的 Unicode 字符（例如，替换成 '?', 抛出异常等）。

4. **注册和管理编码器：**
   - 使用 `TextCodecRegistrar` 注册自身支持的编码，使得 Blink 引擎能够识别和使用这些编解码器。
   - 提供 `RegisterEncodingNames` 函数来注册编码的规范名称和别名。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Blink 引擎处理文本编码的核心部分，而文本编码对于正确显示网页内容至关重要。它直接影响到 JavaScript、HTML 和 CSS 中文本的处理。

**HTML:**

- **`<meta charset="...">` 标签：** 当 HTML 文档中指定了 CJK 字符编码时，Blink 引擎会使用 `TextCodecCJK` 中相应的解码器来解析 HTML 内容。
  - **举例：** 如果一个 HTML 文件包含 `<meta charset="GBK">`，浏览器会使用 `TextCodecCJK` 中 GBK 的解码器来解释网页中的汉字。如果解码器出错，可能会出现乱码。
  - **假设输入：** 一个包含汉字 "你好" 的 GBK 编码的 HTML 文件字节流。
  - **预期输出：**  浏览器在内存中将该字节流解码为 Unicode 字符串 "你好"，最终正确渲染在页面上。

**JavaScript:**

- **`TextDecoder` API：** JavaScript 可以使用 `TextDecoder` API 来解码特定编码的字节流。Blink 引擎的 `TextCodecCJK` 提供了 `TextDecoder` 所需的底层解码能力。
  - **举例：**  JavaScript 代码可以使用 `new TextDecoder('shift-jis').decode(bytes)` 来解码 Shift_JIS 编码的字节数组。`TextCodecCJK` 中 Shift_JIS 的解码器会被调用。
  - **假设输入：**  一个包含日文 "こんにちは" 的 Shift_JIS 编码的 `Uint8Array`。
  - **预期输出：**  `TextDecoder.decode()` 方法返回 JavaScript 字符串 "こんにちは"。

- **`TextEncoder` API：** 类似地，JavaScript 的 `TextEncoder` API 使用 Blink 引擎的编码能力将 JavaScript 字符串编码成特定编码的字节流。
  - **举例：**  `new TextEncoder('gbk').encode('你好')` 会使用 `TextCodecCJK` 中 GBK 的编码器将字符串 "你好" 编码成 GBK 的字节数组。
  - **假设输入：** JavaScript 字符串 "你好"。
  - **预期输出：**  一个包含 "你好" 的 GBK 编码的 `Uint8Array`。

**CSS:**

- **CSS 文件编码：** 虽然 CSS 文件本身也有编码，但通常与 HTML 文档的编码一致或者使用 UTF-8。如果 CSS 文件使用了 CJK 编码，`TextCodecCJK` 同样会参与解码过程，确保 CSS 规则中的文本内容（例如，`content` 属性）能够被正确解析。
  - **举例：**  如果一个 CSS 文件使用 GBK 编码，并且包含 `content: "示例";`，`TextCodecCJK` 的 GBK 解码器会确保 "示例" 被正确理解。
  - **假设输入：**  一个包含 GBK 编码文本的 CSS 文件字节流。
  - **预期输出：**  Blink 引擎正确解析 CSS 文件，将 "示例" 理解为对应的 Unicode 字符。

**逻辑推理示例：**

假设我们有一个 EUC-JP 编码的字节序列 `[0xA1, 0xA2]`。根据 EUC-JP 编码规则，这两个字节可能代表一个日文字符。

- **假设输入：**  EUC-JP 编码的字节序列 `[0xA1, 0xA2]`。
- **解码逻辑：** `EucJpDecoder` 会识别到 `0xA1` 是一个前导字节，需要和下一个字节一起解析。然后它会查找 EUC-JP 编码表，找到 `0xA1 0xA2` 对应的 Unicode 字符，例如 'あ' (HIRAGANA LETTER A)。
- **预期输出：**  Unicode 字符串 "あ"。

**用户或编程常见的使用错误：**

1. **HTML 文件声明的编码与实际编码不符：**
   - **错误举例：** HTML 文件内容是 GBK 编码的汉字，但 `<meta charset="UTF-8">`。
   - **结果：** 浏览器会使用 UTF-8 解码器来解析 GBK 编码的字节流，导致出现乱码。

2. **JavaScript 中使用错误的编码名称：**
   - **错误举例：**  尝试使用 `new TextDecoder('gb2312').decode(bytes)` 解码 GBK 编码的数据。虽然 'gb2312' 是 GBK 的一个别名，但如果引擎内部的映射关系不正确，可能会导致解码失败或乱码。应该使用规范的名称 'gbk' 或 'gb18030'。

3. **服务器发送错误的 `Content-Type` 头部：**
   - **错误举例：** 服务器发送了 GBK 编码的 HTML 文件，但 `Content-Type` 头部设置为 `text/html; charset=UTF-8`。
   - **结果：** 浏览器可能会错误地使用 UTF-8 解码，导致乱码。

4. **在不同编码之间错误地复制粘贴文本：**
   - **错误举例：**  从一个 GBK 编码的文档复制汉字，粘贴到一个期望 UTF-8 编码的编辑器中，如果没有进行正确的编码转换，可能会导致粘贴后的文本显示为乱码。

5. **程序中硬编码了错误的编码假设：**
   - **错误举例：**  一个处理文本文件的程序始终假设文件是 UTF-8 编码，但实际遇到 GBK 编码的文件时，就会出现解析错误。

总而言之，`text_codec_cjk.cc` 文件是 Blink 引擎处理 CJK 字符编码的关键组件，它确保了网页内容（包括 HTML、JavaScript 和 CSS 中的文本）能够被正确地解析和显示，避免出现乱码等问题。理解其功能对于前端开发和解决字符编码相关问题至关重要。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/text_codec_cjk.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2020 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/wtf/text/text_codec_cjk.h"

#include <utility>

#include "base/feature_list.h"
#include "base/functional/function_ref.h"
#include "base/memory/ptr_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/encoding_tables.h"
#include "third_party/blink/renderer/platform/wtf/text/string_concatenate.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace WTF {

class TextCodecCJK::Decoder {
 public:
  virtual ~Decoder() = default;
  virtual String Decode(base::span<const uint8_t> bytes,
                        bool flush,
                        bool stop_on_error,
                        bool& saw_error);

 protected:
  enum class SawError { kNo, kYes };
  virtual SawError ParseByte(uint8_t byte, StringBuilder& result) = 0;
  virtual void Finalize(bool flush, StringBuilder& result) {}

  uint8_t lead_ = 0x00;
  std::optional<uint8_t> prepended_byte_;
};

namespace {

constexpr char kCanonicalNameEucJp[] = "EUC-JP";
constexpr char kCanonicalNameShiftJis[] = "Shift_JIS";
constexpr char kCanonicalNameEucKr[] = "EUC-KR";
constexpr char kCanonicalNameIso2022Jp[] = "ISO-2022-JP";
constexpr char kCanonicalNameGbk[] = "GBK";
constexpr char kCanonicalNameGb18030[] = "gb18030";

constexpr std::array<const char*, 6> kSupportedCanonicalNames{
    kCanonicalNameEucJp,     kCanonicalNameShiftJis, kCanonicalNameEucKr,
    kCanonicalNameIso2022Jp, kCanonicalNameGbk,      kCanonicalNameGb18030,
};

void AppendUnencodableReplacement(UChar32 code_point,
                                  UnencodableHandling handling,
                                  Vector<uint8_t>& result) {
  std::string replacement =
      TextCodec::GetUnencodableReplacement(code_point, handling);
  result.reserve(result.size() + replacement.size());
  for (uint8_t r : replacement) {
    result.UncheckedAppend(r);
  }
}

std::optional<UChar> FindCodePointInJis0208(uint16_t pointer) {
  return FindFirstInSortedPairs(EnsureJis0208EncodeIndexForDecode(), pointer);
}

std::optional<UChar> FindCodePointJis0212(uint16_t pointer) {
  return FindFirstInSortedPairs(EnsureJis0212EncodeIndexForDecode(), pointer);
}

// https://encoding.spec.whatwg.org/#euc-jp-encoder
Vector<uint8_t> EncodeEucJp(StringView string, UnencodableHandling handling) {
  Vector<uint8_t> result;
  result.ReserveInitialCapacity(string.length());

  for (UChar32 code_point : string) {
    if (IsASCII(code_point)) {
      result.push_back(code_point);
      continue;
    }
    if (code_point == kYenSignCharacter) {
      result.push_back(0x5C);
      continue;
    }
    if (code_point == kOverlineCharacter) {
      result.push_back(0x7E);
      continue;
    }
    if (code_point >= 0xFF61 && code_point <= 0xFF9F) {
      result.push_back(0x8E);
      result.push_back(code_point - 0xFF61 + 0xA1);
      continue;
    }
    if (code_point == kMinusSignCharacter)
      code_point = 0xFF0D;

    auto pointer =
        FindFirstInSortedPairs(EnsureJis0208EncodeIndexForEncode(), code_point);
    if (!pointer) {
      AppendUnencodableReplacement(code_point, handling, result);
      continue;
    }
    result.push_back(*pointer / 94 + 0xA1);
    result.push_back(*pointer % 94 + 0xA1);
  }
  return result;
}

class Iso2022JpEncoder {
 public:
  static Vector<uint8_t> Encode(StringView string,
                                UnencodableHandling handling) {
    Iso2022JpEncoder encoder(handling, string.length());
    for (UChar32 code_point : string) {
      encoder.ParseCodePoint(code_point);
    }
    return encoder.Finalize();
  }

 private:
  enum class State : uint8_t { kAscii, kRoman, kJis0208 };

  // From https://encoding.spec.whatwg.org/index-iso-2022-jp-katakana.txt
  static constexpr std::array<UChar32, 63> kIso2022JpKatakana{
      0x3002, 0x300C, 0x300D, 0x3001, 0x30FB, 0x30F2, 0x30A1, 0x30A3, 0x30A5,
      0x30A7, 0x30A9, 0x30E3, 0x30E5, 0x30E7, 0x30C3, 0x30FC, 0x30A2, 0x30A4,
      0x30A6, 0x30A8, 0x30AA, 0x30AB, 0x30AD, 0x30AF, 0x30B1, 0x30B3, 0x30B5,
      0x30B7, 0x30B9, 0x30BB, 0x30BD, 0x30BF, 0x30C1, 0x30C4, 0x30C6, 0x30C8,
      0x30CA, 0x30CB, 0x30CC, 0x30CD, 0x30CE, 0x30CF, 0x30D2, 0x30D5, 0x30D8,
      0x30DB, 0x30DE, 0x30DF, 0x30E0, 0x30E1, 0x30E2, 0x30E4, 0x30E6, 0x30E8,
      0x30E9, 0x30EA, 0x30EB, 0x30EC, 0x30ED, 0x30EF, 0x30F3, 0x309B, 0x309C};
  static_assert(std::size(kIso2022JpKatakana) == 0xFF9F - 0xFF61 + 1);

  Iso2022JpEncoder(UnencodableHandling handling, wtf_size_t length)
      : handling_(handling) {
    result_.ReserveInitialCapacity(length);
  }

  void ChangeStateToAscii() {
    result_.push_back(0x1B);
    result_.push_back(0x28);
    result_.push_back(0x42);
    state_ = State::kAscii;
  }

  void ChangeStateToRoman() {
    result_.push_back(0x1B);
    result_.push_back(0x28);
    result_.push_back(0x4A);
    state_ = State::kRoman;
  }

  void ChangeStateToJis0208() {
    result_.push_back(0x1B);
    result_.push_back(0x24);
    result_.push_back(0x42);
    state_ = State::kJis0208;
  }

  void ParseCodePoint(UChar32 code_point) {
    if ((state_ == State::kAscii || state_ == State::kRoman) &&
        (code_point == 0x000E || code_point == 0x000F ||
         code_point == 0x001B)) {
      StatefulUnencodableHandler(kReplacementCharacter);
      return;
    }
    if (state_ == State::kAscii && IsASCII(code_point)) {
      result_.push_back(code_point);
      return;
    }
    if (state_ == State::kRoman) {
      if (IsASCII(code_point) && code_point != 0x005C && code_point != 0x007E) {
        result_.push_back(code_point);
        return;
      }
      if (code_point == kYenSignCharacter) {
        result_.push_back(0x5C);
        return;
      }
      if (code_point == kOverlineCharacter) {
        result_.push_back(0x7E);
        return;
      }
    }
    if (IsASCII(code_point) && state_ != State::kAscii) {
      ChangeStateToAscii();
      ParseCodePoint(code_point);
      return;
    }
    if ((code_point == kYenSignCharacter || code_point == kOverlineCharacter) &&
        state_ != State::kRoman) {
      ChangeStateToRoman();
      ParseCodePoint(code_point);
      return;
    }
    if (code_point == kMinusSignCharacter)
      code_point = 0xFF0D;
    if (code_point >= 0xFF61 && code_point <= 0xFF9F) {
      code_point = kIso2022JpKatakana[code_point - 0xFF61];
    }

    auto pointer =
        FindFirstInSortedPairs(EnsureJis0208EncodeIndexForEncode(), code_point);
    if (!pointer) {
      StatefulUnencodableHandler(code_point);
      return;
    }
    if (state_ != State::kJis0208) {
      ChangeStateToJis0208();
      ParseCodePoint(code_point);
      return;
    }
    result_.push_back(*pointer / 94 + 0x21);
    result_.push_back(*pointer % 94 + 0x21);
  }

  Vector<uint8_t> Finalize() {
    if (state_ != State::kAscii) {
      ChangeStateToAscii();
    }
    return std::move(result_);
  }

  void StatefulUnencodableHandler(UChar32 code_point) {
    if (state_ == State::kJis0208)
      ChangeStateToAscii();
    AppendUnencodableReplacement(code_point, handling_, result_);
  }

  UnencodableHandling handling_;
  State state_ = State::kAscii;
  Vector<uint8_t> result_;
};

// https://encoding.spec.whatwg.org/#iso-2022-jp-encoder
Vector<uint8_t> EncodeIso2022Jp(StringView string,
                                UnencodableHandling handling) {
  return Iso2022JpEncoder::Encode(string, handling);
}

// https://encoding.spec.whatwg.org/#shift_jis-encoder
Vector<uint8_t> EncodeShiftJis(StringView string,
                               UnencodableHandling handling) {
  Vector<uint8_t> result;
  result.ReserveInitialCapacity(string.length());

  for (UChar32 code_point : string) {
    if (IsASCII(code_point) || code_point == 0x0080) {
      result.push_back(code_point);
      continue;
    }
    if (code_point == kYenSignCharacter) {
      result.push_back(0x5C);
      continue;
    }
    if (code_point == kOverlineCharacter) {
      result.push_back(0x7E);
      continue;
    }
    if (code_point >= 0xFF61 && code_point <= 0xFF9F) {
      result.push_back(code_point - 0xFF61 + 0xA1);
      continue;
    }
    if (code_point == kMinusSignCharacter)
      code_point = 0xFF0D;

    auto range =
        FindInSortedPairs(EnsureJis0208EncodeIndexForEncode(), code_point);
    if (range.first == range.second) {
      AppendUnencodableReplacement(code_point, handling, result);
      continue;
    }

    DCHECK(range.first + 3 >= range.second);
    for (auto pair = range.first; pair < range.second; pair++) {
      uint16_t pointer = pair->second;
      if (pointer >= 8272 && pointer <= 8835)
        continue;
      uint8_t lead = pointer / 188;
      uint8_t lead_offset = lead < 0x1F ? 0x81 : 0xC1;
      uint8_t trail = pointer % 188;
      uint8_t offset = trail < 0x3F ? 0x40 : 0x41;
      result.push_back(lead + lead_offset);
      result.push_back(trail + offset);
      break;
    }
  }
  return result;
}

// https://encoding.spec.whatwg.org/#euc-kr-encoder
Vector<uint8_t> EncodeEucKr(StringView string, UnencodableHandling handling) {
  Vector<uint8_t> result;
  result.ReserveInitialCapacity(string.length());

  for (UChar32 code_point : string) {
    if (IsASCII(code_point)) {
      result.push_back(code_point);
      continue;
    }

    auto pointer =
        FindFirstInSortedPairs(EnsureEucKrEncodeIndexForEncode(), code_point);
    if (!pointer) {
      AppendUnencodableReplacement(code_point, handling, result);
      continue;
    }
    result.push_back(*pointer / 190 + 0x81);
    result.push_back(*pointer % 190 + 0x41);
  }
  return result;
}

// https://encoding.spec.whatwg.org/index-gb18030-ranges.txt
const std::array<std::pair<uint32_t, UChar32>, 207>& Gb18030Ranges() {
  static std::array<std::pair<uint32_t, UChar32>, 207> ranges{
      {{0, 0x0080},     {36, 0x00A5},    {38, 0x00A9},     {45, 0x00B2},
       {50, 0x00B8},    {81, 0x00D8},    {89, 0x00E2},     {95, 0x00EB},
       {96, 0x00EE},    {100, 0x00F4},   {103, 0x00F8},    {104, 0x00FB},
       {105, 0x00FD},   {109, 0x0102},   {126, 0x0114},    {133, 0x011C},
       {148, 0x012C},   {172, 0x0145},   {175, 0x0149},    {179, 0x014E},
       {208, 0x016C},   {306, 0x01CF},   {307, 0x01D1},    {308, 0x01D3},
       {309, 0x01D5},   {310, 0x01D7},   {311, 0x01D9},    {312, 0x01DB},
       {313, 0x01DD},   {341, 0x01FA},   {428, 0x0252},    {443, 0x0262},
       {544, 0x02C8},   {545, 0x02CC},   {558, 0x02DA},    {741, 0x03A2},
       {742, 0x03AA},   {749, 0x03C2},   {750, 0x03CA},    {805, 0x0402},
       {819, 0x0450},   {820, 0x0452},   {7922, 0x2011},   {7924, 0x2017},
       {7925, 0x201A},  {7927, 0x201E},  {7934, 0x2027},   {7943, 0x2031},
       {7944, 0x2034},  {7945, 0x2036},  {7950, 0x203C},   {8062, 0x20AD},
       {8148, 0x2104},  {8149, 0x2106},  {8152, 0x210A},   {8164, 0x2117},
       {8174, 0x2122},  {8236, 0x216C},  {8240, 0x217A},   {8262, 0x2194},
       {8264, 0x219A},  {8374, 0x2209},  {8380, 0x2210},   {8381, 0x2212},
       {8384, 0x2216},  {8388, 0x221B},  {8390, 0x2221},   {8392, 0x2224},
       {8393, 0x2226},  {8394, 0x222C},  {8396, 0x222F},   {8401, 0x2238},
       {8406, 0x223E},  {8416, 0x2249},  {8419, 0x224D},   {8424, 0x2253},
       {8437, 0x2262},  {8439, 0x2268},  {8445, 0x2270},   {8482, 0x2296},
       {8485, 0x229A},  {8496, 0x22A6},  {8521, 0x22C0},   {8603, 0x2313},
       {8936, 0x246A},  {8946, 0x249C},  {9046, 0x254C},   {9050, 0x2574},
       {9063, 0x2590},  {9066, 0x2596},  {9076, 0x25A2},   {9092, 0x25B4},
       {9100, 0x25BE},  {9108, 0x25C8},  {9111, 0x25CC},   {9113, 0x25D0},
       {9131, 0x25E6},  {9162, 0x2607},  {9164, 0x260A},   {9218, 0x2641},
       {9219, 0x2643},  {11329, 0x2E82}, {11331, 0x2E85},  {11334, 0x2E89},
       {11336, 0x2E8D}, {11346, 0x2E98}, {11361, 0x2EA8},  {11363, 0x2EAB},
       {11366, 0x2EAF}, {11370, 0x2EB4}, {11372, 0x2EB8},  {11375, 0x2EBC},
       {11389, 0x2ECB}, {11682, 0x2FFC}, {11686, 0x3004},  {11687, 0x3018},
       {11692, 0x301F}, {11694, 0x302A}, {11714, 0x303F},  {11716, 0x3094},
       {11723, 0x309F}, {11725, 0x30F7}, {11730, 0x30FF},  {11736, 0x312A},
       {11982, 0x322A}, {11989, 0x3232}, {12102, 0x32A4},  {12336, 0x3390},
       {12348, 0x339F}, {12350, 0x33A2}, {12384, 0x33C5},  {12393, 0x33CF},
       {12395, 0x33D3}, {12397, 0x33D6}, {12510, 0x3448},  {12553, 0x3474},
       {12851, 0x359F}, {12962, 0x360F}, {12973, 0x361B},  {13738, 0x3919},
       {13823, 0x396F}, {13919, 0x39D1}, {13933, 0x39E0},  {14080, 0x3A74},
       {14298, 0x3B4F}, {14585, 0x3C6F}, {14698, 0x3CE1},  {15583, 0x4057},
       {15847, 0x4160}, {16318, 0x4338}, {16434, 0x43AD},  {16438, 0x43B2},
       {16481, 0x43DE}, {16729, 0x44D7}, {17102, 0x464D},  {17122, 0x4662},
       {17315, 0x4724}, {17320, 0x472A}, {17402, 0x477D},  {17418, 0x478E},
       {17859, 0x4948}, {17909, 0x497B}, {17911, 0x497E},  {17915, 0x4984},
       {17916, 0x4987}, {17936, 0x499C}, {17939, 0x49A0},  {17961, 0x49B8},
       {18664, 0x4C78}, {18703, 0x4CA4}, {18814, 0x4D1A},  {18962, 0x4DAF},
       {19043, 0x9FA6}, {33469, 0xE76C}, {33470, 0xE7C8},  {33471, 0xE7E7},
       {33484, 0xE815}, {33485, 0xE819}, {33490, 0xE81F},  {33497, 0xE827},
       {33501, 0xE82D}, {33505, 0xE833}, {33513, 0xE83C},  {33520, 0xE844},
       {33536, 0xE856}, {33550, 0xE865}, {37845, 0xF92D},  {37921, 0xF97A},
       {37948, 0xF996}, {38029, 0xF9E8}, {38038, 0xF9F2},  {38064, 0xFA10},
       {38065, 0xFA12}, {38066, 0xFA15}, {38069, 0xFA19},  {38075, 0xFA22},
       {38076, 0xFA25}, {38078, 0xFA2A}, {39108, 0xFE32},  {39109, 0xFE45},
       {39113, 0xFE53}, {39114, 0xFE58}, {39115, 0xFE67},  {39116, 0xFE6C},
       {39265, 0xFF5F}, {39394, 0xFFE6}, {189000, 0x10000}}};
  return ranges;
}

// https://encoding.spec.whatwg.org/#index-gb18030-ranges-code-point
std::optional<UChar32> IndexGb18030RangesCodePoint(uint32_t pointer) {
  if ((pointer > 39419 && pointer < 189000) || pointer > 1237575)
    return std::nullopt;
  if (pointer == 7457)
    return 0xE7C7;

  const auto& gb18030_ranges = Gb18030Ranges();
  auto upper_bound =
      std::upper_bound(gb18030_ranges.begin(), gb18030_ranges.end(),
                       MakeFirstAdapter(pointer), CompareFirst{});
  DCHECK(upper_bound != gb18030_ranges.begin());
  uint32_t offset = (upper_bound - 1)->first;
  UChar32 code_point_offset = (upper_bound - 1)->second;
  return code_point_offset + pointer - offset;
}

// https://encoding.spec.whatwg.org/#index-gb18030-ranges-pointer
uint32_t Gb18030RangesPointer(UChar32 code_point) {
  if (code_point == 0xE7C7)
    return 7457;
  auto upper_bound =
      std::upper_bound(Gb18030Ranges().begin(), Gb18030Ranges().end(),
                       MakeSecondAdapter(code_point), CompareSecond{});
  DCHECK(upper_bound != Gb18030Ranges().begin());
  uint32_t pointer_offset = (upper_bound - 1)->first;
  UChar32 offset = (upper_bound - 1)->second;
  return pointer_offset + code_point - offset;
}

// https://unicode-org.atlassian.net/browse/ICU-22357
// The 2-byte values are handled correctly by values from
// EnsureGb18030EncodeTable() but these need to be exceptions from
// Gb18030Ranges().
static std::optional<uint16_t> Gb18030AsymmetricEncode(UChar32 codePoint) {
  switch (codePoint) {
    case 0xE81E:
      return 0xFE59;
    case 0xE826:
      return 0xFE61;
    case 0xE82B:
      return 0xFE66;
    case 0xE82C:
      return 0xFE67;
    case 0xE832:
      return 0xFE6D;
    case 0xE843:
      return 0xFE7E;
    case 0xE854:
      return 0xFE90;
    case 0xE864:
      return 0xFEA0;
    case 0xE78D:
      return 0xA6D9;
    case 0xE78F:
      return 0xA6DB;
    case 0xE78E:
      return 0xA6DA;
    case 0xE790:
      return 0xA6DC;
    case 0xE791:
      return 0xA6DD;
    case 0xE792:
      return 0xA6DE;
    case 0xE793:
      return 0xA6DF;
    case 0xE794:
      return 0xA6EC;
    case 0xE795:
      return 0xA6ED;
    case 0xE796:
      return 0xA6F3;
  }
  return std::nullopt;
}

// https://encoding.spec.whatwg.org/#gb18030-encoder
enum class IsGbk : bool { kNo, kYes };
Vector<uint8_t> EncodeGbShared(StringView string,
                               UnencodableHandling handling,
                               IsGbk is_gbk) {
  Vector<uint8_t> result;
  result.ReserveInitialCapacity(string.length());

  for (UChar32 code_point : string) {
    if (IsASCII(code_point)) {
      result.push_back(code_point);
      continue;
    }
    if (code_point == 0xE5E5) {
      AppendUnencodableReplacement(code_point, handling, result);
      continue;
    }
    if (is_gbk == IsGbk::kYes && code_point == 0x20AC) {
      result.push_back(0x80);
      continue;
    }
    if (auto encoded = Gb18030AsymmetricEncode(code_point)) {
      result.push_back(*encoded >> 8);
      result.push_back(*encoded);
      continue;
    }
    auto pointer_range =
        FindInSortedPairs(EnsureGb18030EncodeIndexForEncode(), code_point);
    if (pointer_range.first != pointer_range.second) {
      uint16_t pointer = pointer_range.first->second;
      uint8_t lead = pointer / 190 + 0x81;
      uint8_t trail = pointer % 190;
      uint8_t offset = trail < 0x3F ? 0x40 : 0x41;
      result.push_back(lead);
      result.push_back(trail + offset);
      continue;
    }
    if (is_gbk == IsGbk::kYes) {
      AppendUnencodableReplacement(code_point, handling, result);
      continue;
    }
    uint32_t pointer = Gb18030RangesPointer(code_point);
    uint8_t byte1 = pointer / (10 * 126 * 10);
    pointer = pointer % (10 * 126 * 10);
    uint8_t byte2 = pointer / (10 * 126);
    pointer = pointer % (10 * 126);
    uint8_t byte3 = pointer / 10;
    uint8_t byte4 = pointer % 10;
    result.push_back(byte1 + 0x81);
    result.push_back(byte2 + 0x30);
    result.push_back(byte3 + 0x81);
    result.push_back(byte4 + 0x30);
  }
  return result;
}

Vector<uint8_t> EncodeGb18030(StringView string, UnencodableHandling handling) {
  return EncodeGbShared(string, handling, IsGbk::kNo);
}

Vector<uint8_t> EncodeGbk(StringView string, UnencodableHandling handling) {
  return EncodeGbShared(string, handling, IsGbk::kYes);
}

// https://encoding.spec.whatwg.org/#euc-jp-decoder
class EucJpDecoder : public TextCodecCJK::Decoder {
 public:
  EucJpDecoder() = default;

 protected:
  SawError ParseByte(uint8_t byte, StringBuilder& result) override {
    if (uint8_t lead = std::exchange(lead_, 0x00)) {
      if (lead == 0x8E && byte >= 0xA1 && byte <= 0xDF) {
        result.Append(0xFF61 - 0xA1 + byte);
        return SawError::kNo;
      }
      if (lead == 0x8F && byte >= 0xA1 && byte <= 0xFE) {
        jis0212_ = true;
        lead_ = byte;
        return SawError::kNo;
      }
      if (lead >= 0xA1 && lead <= 0xFE && byte >= 0xA1 && byte <= 0xFE) {
        uint16_t pointer = (lead - 0xA1) * 94 + byte - 0xA1;
        if (auto code_point = std::exchange(jis0212_, false)
                                  ? FindCodePointJis0212(pointer)
                                  : FindCodePointInJis0208(pointer)) {
          result.Append(*code_point);
          return SawError::kNo;
        }
      }
      if (IsASCII(byte))
        prepended_byte_ = byte;
      return SawError::kYes;
    }
    if (IsASCII(byte)) {
      result.Append(static_cast<char>(byte));
      return SawError::kNo;
    }
    if (byte == 0x8E || byte == 0x8F || (byte >= 0xA1 && byte <= 0xFE)) {
      lead_ = byte;
      return SawError::kNo;
    }
    return SawError::kYes;
  }

 private:
  bool jis0212_ = false;
};

// https://encoding.spec.whatwg.org/#iso-2022-jp-decoder
class Iso2022JpDecoder : public TextCodecCJK::Decoder {
 public:
  Iso2022JpDecoder() = default;

  String Decode(base::span<const uint8_t> bytes,
                bool flush,
                bool stop_on_error,
                bool& saw_error) override {
    StringBuilder result;
    result.ReserveCapacity(bytes.size());

    if (prepended_byte_ &&
        ParseByte(*std::exchange(prepended_byte_, std::nullopt), result) ==
            SawError::kYes) {
      saw_error = true;
      result.Append(kReplacementCharacter);
      if (stop_on_error) {
        lead_ = 0x00;
        return result.ToString();
      }
    }
    if (second_prepended_byte_ &&
        ParseByte(*std::exchange(second_prepended_byte_, std::nullopt),
                  result) == SawError::kYes &&
        stop_on_error) {
      saw_error = true;
      result.Append(kReplacementCharacter);
      if (stop_on_error) {
        lead_ = 0x00;
        return result.ToString();
      }
    }
    for (size_t i = 0; i < bytes.size(); ++i) {
      if (ParseByte(bytes[i], result) == SawError::kYes) {
        saw_error = true;
        result.Append(kReplacementCharacter);
        if (stop_on_error) {
          lead_ = 0x00;
          return result.ToString();
        }
      }
      if (prepended_byte_ &&
          ParseByte(*std::exchange(prepended_byte_, std::nullopt), result) ==
              SawError::kYes) {
        saw_error = true;
        result.Append(kReplacementCharacter);
        if (stop_on_error) {
          lead_ = 0x00;
          return result.ToString();
        }
      }
      if (second_prepended_byte_ &&
          ParseByte(*std::exchange(second_prepended_byte_, std::nullopt),
                    result) == SawError::kYes &&
          stop_on_error) {
        saw_error = true;
        result.Append(kReplacementCharacter);
        if (stop_on_error) {
          lead_ = 0x00;
          return result.ToString();
        }
      }
    }

    if (flush) {
      switch (decoder_state_) {
        case State::kAscii:
        case State::kRoman:
        case State::kKatakana:
        case State::kLeadByte:
          break;
        case State::kTrailByte:
          decoder_state_ = State::kLeadByte;
          [[fallthrough]];
        case State::kEscapeStart:
          saw_error = true;
          result.Append(kReplacementCharacter);
          break;
        case State::kEscape:
          saw_error = true;
          result.Append(kReplacementCharacter);
          if (lead_) {
            DCHECK(IsASCII(lead_));
            result.Append(std::exchange(lead_, 0x00));
          }
          break;
      }
    }

    return result.ToString();
  }

 protected:
  SawError ParseByte(uint8_t byte, StringBuilder& result) override {
    switch (decoder_state_) {
      case State::kAscii:
        if (byte == 0x1B) {
          decoder_state_ = State::kEscapeStart;
          break;
        }
        if (byte <= 0x7F && byte != 0x0E && byte != 0x0F && byte != 0x1B) {
          output_ = false;
          result.Append(byte);
          break;
        }
        output_ = false;
        return SawError::kYes;
      case State::kRoman:
        if (byte == 0x1B) {
          decoder_state_ = State::kEscapeStart;
          break;
        }
        if (byte == 0x5C) {
          output_ = false;
          result.Append(static_cast<UChar>(kYenSignCharacter));
          break;
        }
        if (byte == 0x7E) {
          output_ = false;
          result.Append(static_cast<UChar>(kOverlineCharacter));
          break;
        }
        if (byte <= 0x7F && byte != 0x0E && byte != 0x0F && byte != 0x1B &&
            byte != 0x5C && byte != 0x7E) {
          output_ = false;
          result.Append(byte);
          break;
        }
        output_ = false;
        return SawError::kYes;
      case State::kKatakana:
        if (byte == 0x1B) {
          decoder_state_ = State::kEscapeStart;
          break;
        }
        if (byte >= 0x21 && byte <= 0x5F) {
          output_ = false;
          result.Append(static_cast<UChar>(0xFF61 - 0x21 + byte));
          break;
        }
        output_ = false;
        return SawError::kYes;
      case State::kLeadByte:
        if (byte == 0x1B) {
          decoder_state_ = State::kEscapeStart;
          break;
        }
        if (byte >= 0x21 && byte <= 0x7E) {
          output_ = false;
          lead_ = byte;
          decoder_state_ = State::kTrailByte;
          break;
        }
        output_ = false;
        return SawError::kYes;
      case State::kTrailByte:
        if (byte == 0x1B) {
          decoder_state_ = State::kEscapeStart;
          return SawError::kYes;
        }
        decoder_state_ = State::kLeadByte;
        if (byte >= 0x21 && byte <= 0x7E) {
          uint16_t pointer = (lead_ - 0x21) * 94 + byte - 0x21;
          if (auto code_point = FindCodePointInJis0208(pointer)) {
            result.Append(*code_point);
            break;
          }
          return SawError::kYes;
        }
        return SawError::kYes;
      case State::kEscapeStart:
        if (byte == 0x24 || byte == 0x28) {
          lead_ = byte;
          decoder_state_ = State::kEscape;
          break;
        }
        prepended_byte_ = byte;
        output_ = false;
        decoder_state_ = decoder_output_state_;
        return SawError::kYes;
      case State::kEscape: {
        uint8_t lead = std::exchange(lead_, 0x00);
        std::optional<State> state;
        if (lead == 0x28) {
          if (byte == 0x42)
            state = State::kAscii;
          else if (byte == 0x4A)
            state = State::kRoman;
          else if (byte == 0x49)
            state = State::kKatakana;
        } else if (lead == 0x24 && (byte == 0x40 || byte == 0x42)) {
          state = State::kLeadByte;
        }
        if (state) {
          decoder_state_ = *state;
          decoder_output_state_ = *state;
          if (std::exchange(output_, true))
            return SawError::kYes;
          break;
        }
        prepended_byte_ = lead;
        second_prepended_byte_ = byte;
        output_ = false;
        decoder_state_ = decoder_output_state_;
        return SawError::kYes;
      }
    }
    return SawError::kNo;
  }

 private:
  enum class State {
    kAscii,
    kRoman,
    kKatakana,
    kLeadByte,
    kTrailByte,
    kEscapeStart,
    kEscape
  };
  State decoder_state_ = State::kAscii;
  State decoder_output_state_ = State::kAscii;
  bool output_ = false;
  std::optional<uint8_t> second_prepended_byte_;
};

// https://encoding.spec.whatwg.org/#shift_jis-decoder
class ShiftJisDecoder : public TextCodecCJK::Decoder {
 public:
  ShiftJisDecoder() = default;

 protected:
  SawError ParseByte(uint8_t byte, StringBuilder& result) override {
    if (uint8_t lead = std::exchange(lead_, 0x00)) {
      uint8_t offset = byte < 0x7F ? 0x40 : 0x41;
      uint8_t lead_offset = lead < 0xA0 ? 0x81 : 0xC1;
      if ((byte >= 0x40 && byte <= 0x7E) || (byte >= 0x80 && byte <= 0xFC)) {
        uint16_t pointer = (lead - lead_offset) * 188 + byte - offset;
        if (pointer >= 8836 && pointer <= 10715) {
          result.Append(static_cast<UChar>(0xE000 - 8836 + pointer));
          return SawError::kNo;
        }
        if (auto code_point = FindCodePointInJis0208(pointer)) {
          result.Append(*code_point);
          return SawError::kNo;
        }
      }
      if (IsASCII(byte))
        prepended_byte_ = byte;
      return SawError::kYes;
    }
    if (IsASCII(byte) || byte == 0x80) {
      result.Append(byte);
      return SawError::kNo;
    }
    if (byte >= 0xA1 && byte <= 0xDF) {
      result.Append(static_cast<UChar>(0xFF61 - 0xA1 + byte));
      return SawError::kNo;
    }
    if ((byte >= 0x81 && byte <= 0x9F) || (byte >= 0xE0 && byte <= 0xFC)) {
      lead_ = byte;
      return SawError::kNo;
    }
    return SawError::kYes;
  }
};

// https://encoding.spec.whatwg.org/#euc-kr-decoder
class EucKrDecoder : public TextCodecCJK::Decoder {
 public:
  EucKrDecoder() = default;

 protected:
  SawError ParseByte(uint8_t byte, StringBuilder& result) override {
    if (uint8_t lead = std::exchange(lead_, 0x00)) {
      if (byte >= 0x41 && byte <= 0xFE) {
        if (auto code_point =
                FindFirstInSortedPairs(EnsureEucKrEncodeIndexForDecode(),
                                       (lead - 0x81) * 190 + byte - 0x41)) {
          result.Append(*code_point);
          return SawError::kNo;
        }
      }
      if (IsASCII(byte))
        prepended_byte_ = byte;
      return SawError::kYes;
    }
    if (IsASCII(byte)) {
      result.Append(byte);
      return SawError::kNo;
    }
    if (byte >= 0x81 && byte <= 0xFE) {
      lead_ = byte;
      return SawError::kNo;
    }
    return SawError::kYes;
  }
};

// https://encoding.spec.whatwg.org/#gb18030-decoder
// https://encoding.spec.whatwg.org/#gbk-decoder
// Note that the same decoder is used for GB18030 and GBK.
class Gb18030Decoder : public TextCodecCJK::Decoder {
 public:
  Gb18030Decoder() = default;

  String Decode(base::span<const uint8_t> bytes,
                bool flush,
                bool stop_on_error,
                bool& saw_error) override {
    saw_error_ = &saw_error;
    String result =
        TextCodecCJK::Decoder::Decode(bytes, flush, stop_on_error, saw_error);
    // Ensures that `saw_error_` won't be used for the next run.
    saw_error_ = nullptr;
    return result;
  }

  SawError ParseByte(uint8_t byte, StringBuilder& result) override {
    DCHECK(saw_error_);
    if (third_) {
      if (byte < 0x30 || byte > 0x39) {
        *saw_error_ = true;
        result.Append(kReplacementCharacter);
        first_ = 0x00;
        uint8_t second = std::exchange(second_, 0x00);
        uint8_t third = std::exchange(third_, 0x00);
        if (ParseByte(second, result) == SawError::kYes) {
          *saw_error_ = true;
          result.Append(kReplacementCharacter);
        }
        if (ParseByte(third, result) == SawError::kYes) {
          *saw_error_ = true;
          result.Append(kReplacementCharacter);
        }
        return ParseByte(byte, result);
      }
      uint8_t first = std::exchange(first_, 0x00);
      uint8_t second = std::exchange(second_, 0x00);
      uint8_t third = std::exchange(third_, 0x00);
      if (auto code_point = IndexGb18030RangesCodePoint(
              ((first - 0x81) * 10 * 126 * 10) + ((second - 0x30) * 10 * 126) +
              ((third - 0x81) * 10) + byte - 0x30)) {
        result.Append(*code_point);
        return SawError::kNo;
      }
      return SawError::kYes;
    }
    if (second_) {
      if (byte >= 0x81 && byte <= 0xFE) {
        third_ = byte;
        return SawError::kNo;
      }
      *saw_error_ = true;
      result.Append(kReplacementCharacter);
      first_ = 0x00;
      if (ParseByte(std::exchange(second_, 0x00), result) == SawError::kYes) {
        *saw_error_ = true;
        result.Append(kReplacementCharacter);
      }
      return ParseByte(byte, result);
    }
    if (first_) {
      if (byte >= 0x30 && byte <= 0x39) {
        second_ = byte;
        return SawError::kNo;
      }
      uint8_t lead = std::exchange(first_, 0x00);
      uint8_t offset = byte < 0x7F ? 0x40 : 0x41;
      if ((byte >= 0x40 && byte <= 0x7E) || (byte >= 0x80 && byte <= 0xFE)) {
        size_t pointer = (lead - 0x81) * 190 + byte - offset;
        if (pointer < EnsureGb18030EncodeTable().size()) {
          result.Append(EnsureGb18030EncodeTable()[pointer]);
          return SawError::kNo;
        }
      }
      if (IsASCII(byte))
        prepended_byte_ = byte;
      return SawError::kYes;
    }
    if (IsASCII(byte)) {
      result.Append(byte);
      return SawError::kNo;
    }
    if (byte == 0x80) {
      result.Append(0x20AC);
      return SawError::kNo;
    }
    if (byte >= 0x81 && byte <= 0xFE) {
      first_ = byte;
      return SawError::kNo;
    }
    return SawError::kYes;
  }

  void Finalize(bool flush, StringBuilder& result) override {
    DCHECK(saw_error_);
    if (flush && (first_ || second_ || third_)) {
      first_ = 0x00;
      second_ = 0x00;
      third_ = 0x00;
      *saw_error_ = true;
      result.Append(kReplacementCharacter);
    }
  }

 private:
  uint8_t first_ = 0x00;
  uint8_t second_ = 0x00;
  uint8_t third_ = 0x00;

  // To share a reference to `saw_error` with `TextCodecCJK::Decoder::Decode`
  // we should keep a pointer to `saw_error`, and use it in `ParseByte` and
  // `Finalize`. Since `saw_error` is given as `TextCodecCJK::Decode` argument,
  // I do not think it is safe to keep the reference after
  // `TextCodecCJK::Decode` finishes.
  bool* saw_error_;
};

}  // namespace

enum class TextCodecCJK::Encoding : uint8_t {
  kEucJp,
  kIso2022Jp,
  kShiftJis,
  kEucKr,
  kGbk,
  kGb18030,
};

TextCodecCJK::TextCodecCJK(Encoding encoding) : encoding_(encoding) {}

void TextCodecCJK::RegisterEncodingNames(EncodingNameRegistrar registrar) {
  // https://encoding.spec.whatwg.org/#names-and-labels
  auto registerAliases = [&](std::initializer_list<const char*> list) {
    for (auto* alias : list)
      registrar(alias, *list.begin());
  };

  registerAliases({kCanonicalNameEucJp, "cseucpkdfmtjapanese", "x-euc-jp"});

  registerAliases({kCanonicalNameShiftJis, "csshiftjis", "ms932", "ms_kanji",
                   "shift-jis", "sjis", "windows-31j", "x-sjis"});

  registerAliases({
      kCanonicalNameEucKr,
      "cseuckr",
      "csksc56011987",
      "iso-ir-149",
      "korean",
      "ks_c_5601-1987",
      "ks_c_5601-1989",
      "ksc5601",
      "ksc_5601",
      "windows-949",
  });

  registerAliases({kCanonicalNameIso2022Jp, "csiso2022jp"});

  registerAliases({kCanonicalNameGbk, "chinese", "csgb2312", "csiso58gb231280",
                   "gb2312", "gb_2312", "gb_2312-80", "iso-ir-58", "x-gbk"});

  registerAliases({kCanonicalNameGb18030});
}

void TextCodecCJK::RegisterCodecs(TextCodecRegistrar registrar) {
  for (auto* name : kSupportedCanonicalNames) {
    registrar(name, Create, nullptr);
  }
}

std::unique_ptr<TextCodec> TextCodecCJK::Create(const TextEncoding& encoding,
                                                const void*) {
  const AtomicString& name = encoding.GetName();

  // To keep the `TextCodecCJK` constructor private, we intend to `new`
  // it and use `base::WrapUnique`. Note that we cannot use `std::make_unique`
  // for a private constructor.
  if (name == kCanonicalNameEucJp) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kEucJp));
  }
  if (name == kCanonicalNameShiftJis) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kShiftJis));
  }
  if (name == kCanonicalNameEucKr) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kEucKr));
  }
  if (name == kCanonicalNameIso2022Jp) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kIso2022Jp));
  }
  if (name == kCanonicalNameGbk) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kGbk));
  }
  if (name == kCanonicalNameGb18030) {
    return base::WrapUnique(new TextCodecCJK(Encoding::kGb18030));
  }
  NOTREACHED();
}

String TextCodecCJK::Decoder::Decode(base::span<const uint8_t> bytes,
                                     bool flush,
                                     bool stop_on_error,
                                     bool& saw_error) {
  StringBuilder result;
  result.ReserveCapacity(bytes.size());

  if (prepended_byte_ &&
      ParseByte(*std::exchange(prepended_byte_, std::nullopt), result) ==
          SawError::kYes) {
    saw_error = true;
    result.Append(kReplacementCharacter);
    if (stop_on_error) {
      lead_ = 0x00;
      return result.ToString();
    }
  }
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (ParseByte(bytes[i], result) == SawError::kYes) {
      saw_error = true;
      result.Append(kReplacementCharacter);
      if (stop_on_error) {
        lead_ = 0x00;
        return result.ToString();
      }
    }
    if (prepended_byte_ &&
        ParseByte(*std::exchange(prepended_byte_, std::nullopt), result) ==
            SawError::kYes) {
      saw_error = true;
      result.Append(kReplacementCharacter);
      if (stop_on_error) {
        lead_ = 0x00;
        return result.ToString();
      }
    }
  }

  if (flush && lead_) {
    lead_ = 0x00;
    saw_error = true;
    result.Append(kReplacementCharacter);
  }

  Finalize(flush, result);
  return result.ToString();
}

String TextCodecCJK::Decode(base::span<const uint8_t> data,
                            FlushBehavior flush_behavior,
                            bool stop_on_error,
                            bool& saw_error) {
  bool flush = flush_behavior != FlushBehavior::kDoNotFlush;
  if (!decoder_) {
    switch (encoding_) {
      case Encoding::kEucJp:
        decoder_ = std::make_unique<EucJpDecoder>();
        break;
      case Encoding::kShiftJis:
        decoder_ = std::make_unique<ShiftJisDecoder>();
        break;
      case Encoding::kIso2022Jp:
        decoder_ = std::make_unique<Iso2022JpDecoder>();
        break;
      case Encoding::kEucKr:
        decoder_ = std::make_unique<EucKrDecoder>();
        break;
      // GBK and GB18030 use the same decoder.
      case Encoding::kGbk:
        ABSL_FALLTHROUGH_INTENDED;
      case Encoding::kGb18030:
        decoder_ = std::make_unique<Gb18030Decoder>();
        break;
    }
  }
  return decoder_->Decode(data, flush, stop_on_error, saw_error);
}

Vector<uint8_t> TextCodecCJK::EncodeCommon(StringView string,
                                           UnencodableHandling handling) const {
  switch (encoding_) {
    case Encoding::kEucJp:
      return EncodeEucJp(string, handling);
    case Encoding::kShiftJis:
      return EncodeShiftJis(string, handling);
    case Encoding::kIso2022Jp:
      return EncodeIso2022Jp(string, handling);
    case Encoding::kEucKr:
      return EncodeEucKr(string, handling);
    case Encoding::kGbk:
      return EncodeGbk(string, handling);
    case Encoding::kGb18030:
      return EncodeGb18030(string, handling);
  }
  NOTREACHED();
}

std::string TextCodecCJK::Encode(base::span<const UChar> characters,
                                 UnencodableHandling handling) {
  Vector<uint8_t> v = EncodeCommon(StringView(characters), handling);
  return std::string(v.begin(), v.end());
}

std::string TextCodecCJK::Encode(base::span<const LChar> characters,
                                 UnencodableHandling handling) {
  Vector<uint8_t> v = EncodeCommon(StringView(characters), handling);
  return std::string(v.begin(), v.end());
}

// static
bool TextCodecCJK::IsSupported(StringView name) {
  for (auto* e : kSupportedCanonicalNames) {
    if (e == name) {
      return true;
    }
  }
  return false;
}

}  // namespace WTF
```
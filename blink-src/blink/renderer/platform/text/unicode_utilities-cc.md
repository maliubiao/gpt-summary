Response:
Let's break down the thought process for analyzing this `unicode_utilities.cc` file.

1. **Initial Scan for Purpose:** The filename itself (`unicode_utilities.cc`) strongly suggests this file contains functions for manipulating and analyzing Unicode text. The copyright notice at the top confirms it's part of a larger project (Apple/Blink/Chromium).

2. **Examine Includes:** The included headers provide crucial clues about the functionality:
    * `<unicode/normalizer2.h>`:  Indicates functions for Unicode normalization (like NFC, NFD).
    * `<unicode/utf16.h>`: Implies dealing with UTF-16 encoding.
    * `"third_party/blink/renderer/platform/wtf/text/character_names.h"`:  Suggests named character constants are used.
    * `"third_party/blink/renderer/platform/wtf/text/string_buffer.h"`: Points to potential string manipulation/building.

3. **Namespace Check:** The code is within the `blink` namespace, which confirms it's part of the Blink rendering engine.

4. **Identify Key Data Structures and Enums:**
    * `VoicedSoundMarkType` enum:  Clearly related to Japanese Kana characters and their diacritics.

5. **Analyze Individual Functions (Iterative Process):**  Go through each function and understand its purpose. Look for patterns and relationships between functions.

    * **`FoldQuoteMarkOrSoftHyphen` (template):**  This function is simple but important. It maps various quote marks to standard single/double quotes and replaces soft hyphens with a null character. This suggests a normalization step for string comparison or processing where these distinctions are irrelevant.

    * **`FoldQuoteMarksAndSoftHyphens` (two overloads):** These apply the `FoldQuoteMarkOrSoftHyphen` logic to either a `base::span<UChar>` or a `String`. The span version operates in-place, while the `String` version uses `Replace`.

    * **`IsNonLatin1Separator`:** Checks if a character (above ASCII) is a separator based on its Unicode general category.

    * **`IsSeparator`:** This is more complex. It has a precomputed `kLatin1SeparatorTable` for ASCII characters and then calls `IsNonLatin1Separator` for others. This is likely used for word breaking or text segmentation.

    * **`ContainsOnlySeparatorsOrEmpty`:**  A helper function to check if a string consists solely of separators or is empty.

    * **Kana Workaround Functions (`IsKanaLetter`, `IsSmallKanaLetter`, `ComposedVoicedSoundMark`, `IsCombiningVoicedSoundMark`, `ContainsKanaLetters`):**  This is a significant block. The comments explicitly explain the "kana workaround" – a strategy to handle nuances in Japanese text comparison that ICU's default collation doesn't address adequately. These functions identify different types of Kana characters and their voicing marks.

    * **`NormalizeCharactersIntoNfc`:**  Uses ICU to normalize a sequence of characters to NFC (Normalization Form Canonical Composition). This is a standard Unicode normalization form. The optimization to avoid full normalization if the input is mostly already NFC is a good touch.

    * **Comparison Functions (`CompareKanaLetterAndComposedVoicedSoundMarks`, `CheckOnlyKanaLettersInStrings`, `CheckKanaStringsEqual`):** These functions implement the "kana workaround." They compare strings, specifically focusing on correctly handling small Kana and voicing marks. The `CompareKanaLetterAndComposedVoicedSoundMarks` function is a low-level helper for comparing individual Kana characters with their diacritics. The other two build upon this.

6. **Identify Relationships to Web Technologies:**  Connect the functions to their potential use cases in a web browser.

    * **JavaScript:** String manipulation, text search/matching (e.g., `String.prototype.includes()`, `String.prototype.indexOf()`), internationalization.
    * **HTML:** Text rendering, text input, form submission, attribute parsing (e.g., `alt` text, accessibility).
    * **CSS:**  Text styling (e.g., handling quotes, whitespace), text selection.

7. **Construct Examples and Scenarios:** Create concrete examples to illustrate how the functions might be used and potential issues.

8. **Consider Common Errors:** Think about how developers might misuse these utilities. For instance, forgetting to normalize strings before comparison, or assuming simple string equality works for all languages.

9. **Structure the Output:** Organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logic/Assumptions, Common Errors) for better readability. Use bullet points and clear explanations.

10. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any missed connections or misunderstandings. For example, initially, I might not have fully grasped the significance of the "kana workaround," but rereading the comments would highlight its importance. Similarly, making sure the examples are diverse and cover different scenarios improves the overall quality of the analysis.
这个 `unicode_utilities.cc` 文件是 Chromium Blink 引擎中负责处理 Unicode 文本的工具函数集合。它的主要功能是提供各种与 Unicode 字符和字符串相关的操作，以便在渲染网页、处理用户输入等过程中正确地处理不同语言和字符。

以下是该文件的功能列表，并根据与 JavaScript、HTML、CSS 的关系进行举例说明：

**主要功能:**

1. **引号和软连字符的折叠 (Folding Quote Marks and Soft Hyphens):**
   - 将各种不同的引号字符（如弯引号、直引号、希伯来引号）统一转换为标准的单引号 (') 或双引号 (")。
   - 将软连字符替换为一个可忽略的字符（空字符 `\0`），这样它们的存在与否不会影响字符串的比较。
   - **与 HTML 的关系:** 当解析 HTML 属性值或文本内容时，可能需要统一引号的表示，以便进行比较或处理。例如，`<a title='你好' href="world">` 和 `<a title=“你好” href=“world”>` 在功能上应该被视为等价的。
   - **与 JavaScript 的关系:** JavaScript 代码中也可能包含不同类型的引号。在某些比较或标准化场景下，可能需要进行这种折叠操作。
   - **与 CSS 的关系:**  CSS 字符串值也可能使用不同类型的引号。虽然 CSS 解析器通常能处理，但在某些内部处理中，统一引号可能是有用的。

   **假设输入与输出:**
   - 输入字符串: `"Left double quote ‘single quote’"`
   - 输出字符串: `"Left double quote 'single quote'"`
   - 输入字符: `kLeftDoubleQuotationMarkCharacter` (U+201C)
   - 输出字符: `"`

2. **判断字符是否为分隔符 (Identifying Separators):**
   - 提供 `IsSeparator(UChar32 character)` 函数，用于判断一个 Unicode 字符是否为分隔符，包括空格、标点符号、控制符等。
   - 使用一个静态查找表 `kLatin1SeparatorTable` 快速判断 ASCII 范围内的字符，对于其他字符则使用更通用的 Unicode 类别判断。
   - **与 HTML 的关系:**  在文本处理、分词、换行等场景中，需要识别分隔符。例如，浏览器在渲染文本时需要根据分隔符来决定如何断行。
   - **与 JavaScript 的关系:** JavaScript 的字符串操作，如 `split()` 方法，依赖于分隔符的概念。此外，在实现文本搜索或分析功能时，也需要判断分隔符。
   - **与 CSS 的关系:** CSS 的 `word-break` 和 `white-space` 属性会影响浏览器如何处理文本中的分隔符和空白。

   **假设输入与输出:**
   - 输入字符: ' ' (空格)
   - 输出: `true`
   - 输入字符: '.' (句号)
   - 输出: `true`
   - 输入字符: 'a'
   - 输出: `false`

3. **判断字符串是否只包含分隔符或为空 (Checking for Only Separators or Empty):**
   - `ContainsOnlySeparatorsOrEmpty(const String& pattern)` 函数检查一个字符串是否只包含分隔符或为空。
   - **与 HTML 的关系:** 可能用于验证某些输入或属性值是否只包含空白或分隔符。
   - **与 JavaScript 的关系:** 在处理用户输入或解析文本时，可能需要判断字符串是否只包含分隔符。

   **假设输入与输出:**
   - 输入字符串: "  \t\n "
   - 输出: `true`
   - 输入字符串: "  hello "
   - 输出: `false`
   - 输入字符串: ""
   - 输出: `true`

4. **处理日语假名 (Kana Workaround):**
   - 提供了一系列函数来处理日语假名字符，包括判断字符是否为假名 (`IsKanaLetter`)、是否为小写假名 (`IsSmallKanaLetter`)、是否带有浊音或半浊音标记 (`ComposedVoicedSoundMark`, `IsCombiningVoicedSoundMark`)。
   - 实现了针对 ICU (International Components for Unicode) 库在假名处理上的一个 "workaround"。ICU 的默认排序规则可能忽略小写假名和浊音/半浊音的区别，但这在实际应用中可能导致搜索或比较结果不符合预期。这些函数用于更精确地比较假名字符串。
   - **与 HTML 的关系:**  当网页内容包含日语文本时，这些函数可以帮助进行更精确的搜索、排序或比较操作。
   - **与 JavaScript 的关系:**  当 JavaScript 代码需要处理日语文本时，例如实现本地化的搜索功能，这些函数提供的更精细的假名比较逻辑非常有用。

   **假设输入与输出:**
   - 输入字符: 'あ' (HIRAGANA LETTER A)
   - `IsKanaLetter` 输出: `true`
   - `IsSmallKanaLetter` 输出: `false`
   - `ComposedVoicedSoundMark` 输出: `kNoVoicedSoundMark`
   - 输入字符: 'が' (HIRAGANA LETTER GA)
   - `IsKanaLetter` 输出: `true`
   - `IsSmallKanaLetter` 输出: `false`
   - `ComposedVoicedSoundMark` 输出: `kVoicedSoundMark`

5. **字符串的 Unicode 规范化 (Unicode Normalization):**
   - `NormalizeCharactersIntoNfc(base::span<const UChar> characters)` 函数将一段字符序列规范化为 NFC (Normalization Form Canonical Composition) 形式。NFC 是一种 Unicode 规范化形式，它将字符组合成尽可能短的表示形式。
   - **与 HTML 的关系:** 在处理 HTML 文本内容或属性值时，进行 Unicode 规范化可以确保具有相同语义的字符序列具有相同的二进制表示，从而方便比较和搜索。例如，`é` 可以由一个单独的字符 U+00E9 表示，也可以由 `e` (U+0065) 和一个组合字符 U+0301 表示。NFC 会将后者转换为前者。
   - **与 JavaScript 的关系:** JavaScript 字符串在进行比较或搜索时，如果涉及到组合字符，可能会出现意想不到的结果。在进行这些操作之前进行规范化可以提高准确性。
   - **与 CSS 的关系:**  理论上，CSS 字符串也应该进行规范化处理，但这通常由底层的文本处理引擎负责。

   **假设输入与输出:**
   - 输入字符序列: 'e' (U+0065), COMBINING ACUTE ACCENT (U+0301)
   - 输出字符序列: 'é' (U+00E9)

6. **比较包含假名的字符串 (Comparing Strings with Kana):**
   - `CheckOnlyKanaLettersInStrings` 和 `CheckKanaStringsEqual` 函数提供了更精细的字符串比较逻辑，特别针对包含假名的情况。它们考虑了小写假名和浊音/半浊音标记的区别，从而避免了 ICU 默认排序规则可能导致的误判。
   - **与 HTML 的关系:**  在网页中搜索日语文本时，或者在比较用户输入的日语文本时，这些函数可以提供更准确的结果.
   - **与 JavaScript 的关系:**  JavaScript 代码中如果需要进行精确的日语字符串比较，可以使用这些函数提供的逻辑。

   **假设输入与输出:**
   - 输入字符串 1: "が"
   - 输入字符串 2: "か"
   - `CheckKanaStringsEqual` 输出: `false` (因为有浊音的区别)
   - 输入字符串 1: "ア"
   - 输入字符串 2: "ァ"
   - `CheckKanaStringsEqual` 输出: `false` (因为有大小写的区别)

**用户或编程常见的使用错误举例:**

1. **未进行 Unicode 规范化就进行字符串比较:**
   - 错误示例 (JavaScript):
     ```javascript
     const str1 = "e\u0301"; // 'e' + combining acute accent
     const str2 = "\xE9";   // é (precomposed)
     console.log(str1 === str2); // 输出: false (因为二进制表示不同)
     ```
   - 正确做法：在比较前进行 NFC 规范化。虽然 JavaScript 没有内置的 NFC 函数，但 Blink 引擎内部使用了 `NormalizeCharactersIntoNfc`。如果需要在 JavaScript 中实现，可以使用第三方库或 polyfill。

2. **忽略软连字符的影响:**
   - 错误示例 (HTML): 假设一个搜索功能没有正确处理软连字符。
     ```html
     <p>This is a very long&#173;word.</p>
     ```
     用户搜索 "longword" 可能无法匹配到包含软连字符的文本，因为软连字符在默认情况下是可见的，会影响字符串的精确匹配。`FoldQuoteMarksAndSoftHyphens` 的作用就是消除这种影响。

3. **在日语文本处理中依赖简单的字符串比较:**
   - 错误示例 (JavaScript):
     ```javascript
     const kana1 = "が";
     const kana2 = "か";
     console.log(kana1 === kana2); // 输出: false
     ```
     虽然这是正确的，但在某些搜索场景下，用户可能希望 "が" 和 "か" 被视为某种程度上的匹配（只是有无浊音的区别）。这时就需要使用 `CheckKanaStringsEqual` 提供的更精细的比较逻辑。

4. **混淆不同类型的引号:**
   - 错误示例 (HTML):
     ```html
     <a title=‘hello’>Click me</a>
     ```
     虽然某些浏览器可能容忍这种写法，但最好使用标准的单引号或双引号。`FoldQuoteMarksAndSoftHyphens` 可以帮助统一这些引号。

总而言之，`unicode_utilities.cc` 提供了一组底层的、高性能的 Unicode 处理工具，Blink 引擎的许多上层功能都依赖于它来正确处理各种文本相关的操作。理解这些功能有助于更好地理解浏览器如何渲染和处理网页上的文本内容，以及在开发 Web 应用时如何避免与 Unicode 相关的常见错误。

Prompt: 
```
这是目录为blink/renderer/platform/text/unicode_utilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2005 Alexey Proskuryakov.
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

#include "third_party/blink/renderer/platform/text/unicode_utilities.h"

#include <unicode/normalizer2.h>
#include <unicode/utf16.h>

#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"

namespace blink {

enum VoicedSoundMarkType {
  kNoVoicedSoundMark,
  kVoicedSoundMark,
  kSemiVoicedSoundMark
};

template <typename CharType>
static inline CharType FoldQuoteMarkOrSoftHyphen(CharType c) {
  switch (static_cast<UChar>(c)) {
    case kHebrewPunctuationGershayimCharacter:
    case kLeftDoubleQuotationMarkCharacter:
    case kRightDoubleQuotationMarkCharacter:
      return '"';
    case kHebrewPunctuationGereshCharacter:
    case kLeftSingleQuotationMarkCharacter:
    case kRightSingleQuotationMarkCharacter:
      return '\'';
    case kSoftHyphenCharacter:
      // Replace soft hyphen with an ignorable character so that their presence
      // or absence will
      // not affect string comparison.
      return 0;
    default:
      return c;
  }
}

void FoldQuoteMarksAndSoftHyphens(base::span<UChar> data) {
  for (UChar& ch : data) {
    ch = FoldQuoteMarkOrSoftHyphen(ch);
  }
}

void FoldQuoteMarksAndSoftHyphens(String& s) {
  s.Replace(kHebrewPunctuationGereshCharacter, '\'');
  s.Replace(kHebrewPunctuationGershayimCharacter, '"');
  s.Replace(kLeftDoubleQuotationMarkCharacter, '"');
  s.Replace(kLeftSingleQuotationMarkCharacter, '\'');
  s.Replace(kRightDoubleQuotationMarkCharacter, '"');
  s.Replace(kRightSingleQuotationMarkCharacter, '\'');
  // Replace soft hyphen with an ignorable character so that their presence or
  // absence will
  // not affect string comparison.
  s.Replace(kSoftHyphenCharacter, static_cast<UChar>('\0'));
}

static bool IsNonLatin1Separator(UChar32 character) {
  DCHECK_GE(character, 256);
  return U_GET_GC_MASK(character) & (U_GC_P_MASK | U_GC_Z_MASK | U_GC_CF_MASK);
}

bool IsSeparator(UChar32 character) {
  // clang-format off
  static constexpr auto kLatin1SeparatorTable = std::to_array<uint8_t>({
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      // space ! " # $ % & ' ( ) * + , - . /
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      //                         : ; < = > ?
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
      //   @
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      //                         [ \ ] ^ _
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
      //   `
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      //                           { | } ~
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
  });
  // clang-format on
  if (character < 256)
    return static_cast<bool>(kLatin1SeparatorTable[character]);

  return IsNonLatin1Separator(character);
}

bool ContainsOnlySeparatorsOrEmpty(const String& pattern) {
  unsigned index = 0;
  while (index < pattern.length()) {
    const UChar32 character = pattern.CharacterStartingAt(index);
    if (!IsSeparator(character)) {
      return false;
    }
    index += U16_LENGTH(character);
  }
  return true;
}

// ICU's search ignores the distinction between small kana letters and ones
// that are not small, and also characters that differ only in the voicing
// marks when considering only primary collation strength differences.
// This is not helpful for end users, since these differences make words
// distinct, so for our purposes we need these to be considered.
// The Unicode folks do not think the collation algorithm should be
// changed. To work around this, we would like to tailor the ICU searcher,
// but we can't get that to work yet. So instead, we check for cases where
// these differences occur, and skip those matches.

// We refer to the above technique as the "kana workaround". The next few
// functions are helper functinos for the kana workaround.

bool IsKanaLetter(UChar character) {
  // Hiragana letters.
  if (character >= 0x3041 && character <= 0x3096)
    return true;

  // Katakana letters.
  if (character >= 0x30A1 && character <= 0x30FA)
    return true;
  if (character >= 0x31F0 && character <= 0x31FF)
    return true;

  // Halfwidth katakana letters.
  if (character >= 0xFF66 && character <= 0xFF9D && character != 0xFF70)
    return true;

  return false;
}

bool IsSmallKanaLetter(UChar character) {
  DCHECK(IsKanaLetter(character));

  switch (character) {
    case 0x3041:  // HIRAGANA LETTER SMALL A
    case 0x3043:  // HIRAGANA LETTER SMALL I
    case 0x3045:  // HIRAGANA LETTER SMALL U
    case 0x3047:  // HIRAGANA LETTER SMALL E
    case 0x3049:  // HIRAGANA LETTER SMALL O
    case 0x3063:  // HIRAGANA LETTER SMALL TU
    case 0x3083:  // HIRAGANA LETTER SMALL YA
    case 0x3085:  // HIRAGANA LETTER SMALL YU
    case 0x3087:  // HIRAGANA LETTER SMALL YO
    case 0x308E:  // HIRAGANA LETTER SMALL WA
    case 0x3095:  // HIRAGANA LETTER SMALL KA
    case 0x3096:  // HIRAGANA LETTER SMALL KE
    case 0x30A1:  // KATAKANA LETTER SMALL A
    case 0x30A3:  // KATAKANA LETTER SMALL I
    case 0x30A5:  // KATAKANA LETTER SMALL U
    case 0x30A7:  // KATAKANA LETTER SMALL E
    case 0x30A9:  // KATAKANA LETTER SMALL O
    case 0x30C3:  // KATAKANA LETTER SMALL TU
    case 0x30E3:  // KATAKANA LETTER SMALL YA
    case 0x30E5:  // KATAKANA LETTER SMALL YU
    case 0x30E7:  // KATAKANA LETTER SMALL YO
    case 0x30EE:  // KATAKANA LETTER SMALL WA
    case 0x30F5:  // KATAKANA LETTER SMALL KA
    case 0x30F6:  // KATAKANA LETTER SMALL KE
    case 0x31F0:  // KATAKANA LETTER SMALL KU
    case 0x31F1:  // KATAKANA LETTER SMALL SI
    case 0x31F2:  // KATAKANA LETTER SMALL SU
    case 0x31F3:  // KATAKANA LETTER SMALL TO
    case 0x31F4:  // KATAKANA LETTER SMALL NU
    case 0x31F5:  // KATAKANA LETTER SMALL HA
    case 0x31F6:  // KATAKANA LETTER SMALL HI
    case 0x31F7:  // KATAKANA LETTER SMALL HU
    case 0x31F8:  // KATAKANA LETTER SMALL HE
    case 0x31F9:  // KATAKANA LETTER SMALL HO
    case 0x31FA:  // KATAKANA LETTER SMALL MU
    case 0x31FB:  // KATAKANA LETTER SMALL RA
    case 0x31FC:  // KATAKANA LETTER SMALL RI
    case 0x31FD:  // KATAKANA LETTER SMALL RU
    case 0x31FE:  // KATAKANA LETTER SMALL RE
    case 0x31FF:  // KATAKANA LETTER SMALL RO
    case 0xFF67:  // HALFWIDTH KATAKANA LETTER SMALL A
    case 0xFF68:  // HALFWIDTH KATAKANA LETTER SMALL I
    case 0xFF69:  // HALFWIDTH KATAKANA LETTER SMALL U
    case 0xFF6A:  // HALFWIDTH KATAKANA LETTER SMALL E
    case 0xFF6B:  // HALFWIDTH KATAKANA LETTER SMALL O
    case 0xFF6C:  // HALFWIDTH KATAKANA LETTER SMALL YA
    case 0xFF6D:  // HALFWIDTH KATAKANA LETTER SMALL YU
    case 0xFF6E:  // HALFWIDTH KATAKANA LETTER SMALL YO
    case 0xFF6F:  // HALFWIDTH KATAKANA LETTER SMALL TU
      return true;
  }
  return false;
}

static inline VoicedSoundMarkType ComposedVoicedSoundMark(UChar character) {
  DCHECK(IsKanaLetter(character));

  switch (character) {
    case 0x304C:  // HIRAGANA LETTER GA
    case 0x304E:  // HIRAGANA LETTER GI
    case 0x3050:  // HIRAGANA LETTER GU
    case 0x3052:  // HIRAGANA LETTER GE
    case 0x3054:  // HIRAGANA LETTER GO
    case 0x3056:  // HIRAGANA LETTER ZA
    case 0x3058:  // HIRAGANA LETTER ZI
    case 0x305A:  // HIRAGANA LETTER ZU
    case 0x305C:  // HIRAGANA LETTER ZE
    case 0x305E:  // HIRAGANA LETTER ZO
    case 0x3060:  // HIRAGANA LETTER DA
    case 0x3062:  // HIRAGANA LETTER DI
    case 0x3065:  // HIRAGANA LETTER DU
    case 0x3067:  // HIRAGANA LETTER DE
    case 0x3069:  // HIRAGANA LETTER DO
    case 0x3070:  // HIRAGANA LETTER BA
    case 0x3073:  // HIRAGANA LETTER BI
    case 0x3076:  // HIRAGANA LETTER BU
    case 0x3079:  // HIRAGANA LETTER BE
    case 0x307C:  // HIRAGANA LETTER BO
    case 0x3094:  // HIRAGANA LETTER VU
    case 0x30AC:  // KATAKANA LETTER GA
    case 0x30AE:  // KATAKANA LETTER GI
    case 0x30B0:  // KATAKANA LETTER GU
    case 0x30B2:  // KATAKANA LETTER GE
    case 0x30B4:  // KATAKANA LETTER GO
    case 0x30B6:  // KATAKANA LETTER ZA
    case 0x30B8:  // KATAKANA LETTER ZI
    case 0x30BA:  // KATAKANA LETTER ZU
    case 0x30BC:  // KATAKANA LETTER ZE
    case 0x30BE:  // KATAKANA LETTER ZO
    case 0x30C0:  // KATAKANA LETTER DA
    case 0x30C2:  // KATAKANA LETTER DI
    case 0x30C5:  // KATAKANA LETTER DU
    case 0x30C7:  // KATAKANA LETTER DE
    case 0x30C9:  // KATAKANA LETTER DO
    case 0x30D0:  // KATAKANA LETTER BA
    case 0x30D3:  // KATAKANA LETTER BI
    case 0x30D6:  // KATAKANA LETTER BU
    case 0x30D9:  // KATAKANA LETTER BE
    case 0x30DC:  // KATAKANA LETTER BO
    case 0x30F4:  // KATAKANA LETTER VU
    case 0x30F7:  // KATAKANA LETTER VA
    case 0x30F8:  // KATAKANA LETTER VI
    case 0x30F9:  // KATAKANA LETTER VE
    case 0x30FA:  // KATAKANA LETTER VO
      return kVoicedSoundMark;
    case 0x3071:  // HIRAGANA LETTER PA
    case 0x3074:  // HIRAGANA LETTER PI
    case 0x3077:  // HIRAGANA LETTER PU
    case 0x307A:  // HIRAGANA LETTER PE
    case 0x307D:  // HIRAGANA LETTER PO
    case 0x30D1:  // KATAKANA LETTER PA
    case 0x30D4:  // KATAKANA LETTER PI
    case 0x30D7:  // KATAKANA LETTER PU
    case 0x30DA:  // KATAKANA LETTER PE
    case 0x30DD:  // KATAKANA LETTER PO
      return kSemiVoicedSoundMark;
  }
  return kNoVoicedSoundMark;
}

static inline bool IsCombiningVoicedSoundMark(UChar character) {
  switch (character) {
    case 0x3099:  // COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK
    case 0x309A:  // COMBINING KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK
      return true;
  }
  return false;
}

bool ContainsKanaLetters(const String& pattern) {
  const unsigned length = pattern.length();
  for (unsigned i = 0; i < length; ++i) {
    if (IsKanaLetter(pattern[i]))
      return true;
  }
  return false;
}

Vector<UChar> NormalizeCharactersIntoNfc(base::span<const UChar> characters) {
  DCHECK(characters.size());

  UErrorCode status = U_ZERO_ERROR;
  const icu::Normalizer2* normalizer = icu::Normalizer2::getNFCInstance(status);
  DCHECK(U_SUCCESS(status));
  int32_t input_length = static_cast<int32_t>(characters.size());
  // copy-on-write.
  icu::UnicodeString normalized(false, characters.data(), input_length);
  // In the vast majority of cases, input is already NFC. Run a quick check
  // to avoid normalizing the entire input unnecessarily.
  int32_t normalized_prefix_length =
      normalizer->spanQuickCheckYes(normalized, status);
  if (normalized_prefix_length < input_length) {
    icu::UnicodeString un_normalized(normalized, normalized_prefix_length);
    normalized.truncate(normalized_prefix_length);
    normalizer->normalizeSecondAndAppend(normalized, un_normalized, status);
  }
  int32_t buffer_size = normalized.length();
  DCHECK(buffer_size);

  Vector<UChar> buffer;
  buffer.resize(static_cast<wtf_size_t>(buffer_size));
  normalized.extract(buffer.data(), buffer_size, status);
  DCHECK(U_SUCCESS(status));
  return buffer;
}

// This function returns kNotFound if |first| and |second| contain different
// Kana letters.  If |first| and |second| contain the same Kana letter then
// function returns offset in characters from |first|.
// Pointers to both strings increase simultaneously so so it is possible to use
// one offset value.
static inline size_t CompareKanaLetterAndComposedVoicedSoundMarks(
    base::span<const UChar>::iterator first,
    base::span<const UChar>::iterator first_end,
    base::span<const UChar>::iterator second,
    base::span<const UChar>::iterator second_end) {
  auto start = first;
  // Check for differences in the kana letter character itself.
  if (IsSmallKanaLetter(*first) != IsSmallKanaLetter(*second))
    return kNotFound;
  if (ComposedVoicedSoundMark(*first) != ComposedVoicedSoundMark(*second))
    return kNotFound;
  ++first;
  ++second;

  // Check for differences in combining voiced sound marks found after the
  // letter.
  while (true) {
    const bool second_is_not_sound_mark =
        second == second_end || !IsCombiningVoicedSoundMark(*second);
    if (first == first_end || !IsCombiningVoicedSoundMark(*first)) {
      return second_is_not_sound_mark ? first - start : kNotFound;
    }
    if (second_is_not_sound_mark)
      return kNotFound;
    if (*first != *second)
      return kNotFound;
    ++first;
    ++second;
  }
}

bool CheckOnlyKanaLettersInStrings(base::span<const UChar> first_data,
                                   base::span<const UChar> second_data) {
  auto a = first_data.begin();
  auto a_end = first_data.end();

  auto b = second_data.begin();
  auto b_end = second_data.end();
  while (true) {
    // Skip runs of non-kana-letter characters. This is necessary so we can
    // correctly handle strings where the |firstData| and |secondData| have
    // different-length runs of characters that match, while still double
    // checking the correctness of matches of kana letters with other kana
    // letters.
    a = std::find_if(a, a_end, IsKanaLetter);
    b = std::find_if(b, b_end, IsKanaLetter);

    // If we reached the end of either the target or the match, we should have
    // reached the end of both; both should have the same number of kana
    // letters.
    if (a == a_end || b == b_end) {
      return a == a_end && b == b_end;
    }

    // Check that single Kana letters in |a| and |b| are the same.
    const size_t offset =
        CompareKanaLetterAndComposedVoicedSoundMarks(a, a_end, b, b_end);
    if (offset == kNotFound)
      return false;

    // Update values of |a| and |b| after comparing.
    a += offset;
    b += offset;
  }
}

bool CheckKanaStringsEqual(base::span<const UChar> first_data,
                           base::span<const UChar> second_data) {
  auto a = first_data.begin();
  auto a_end = first_data.end();

  auto b = second_data.begin();
  auto b_end = second_data.end();
  while (true) {
    // Check for non-kana-letter characters.
    while (a != a_end && !IsKanaLetter(*a) && b != b_end && !IsKanaLetter(*b)) {
      if (*a++ != *b++)
        return false;
    }

    // If we reached the end of either the target or the match, we should have
    // reached the end of both; both should have the same number of kana
    // letters.
    if (a == a_end || b == b_end) {
      return a == a_end && b == b_end;
    }

    if (IsKanaLetter(*a) != IsKanaLetter(*b))
      return false;

    // Check that single Kana letters in |a| and |b| are the same.
    const size_t offset =
        CompareKanaLetterAndComposedVoicedSoundMarks(a, a_end, b, b_end);
    if (offset == kNotFound)
      return false;

    // Update values of |a| and |b| after comparing.
    a += offset;
    b += offset;
  }
}

}  // namespace blink

"""

```
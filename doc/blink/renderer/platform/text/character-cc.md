Response:
Let's break down the thought process for analyzing the `character.cc` file.

**1. Initial Skim and Understanding the Purpose:**

* **Copyright and Headers:** The initial lines give context – it's part of the Chromium Blink engine (rendering engine). The copyright indicates Google's involvement. The `#include` directives point to other Blink/Chromium components (`character.h`, ICU libraries, WTF utilities, base library). This immediately suggests the file deals with character-level operations, likely using Unicode.
* **Namespace:** The code is within the `blink` namespace, further confirming its role within the Blink rendering engine.
* **Focus on `Character`:** The core functionality is clearly centered around the `Character` class and its static methods. This means the file provides utility functions related to character properties and manipulation.

**2. Analyzing Key Sections and Functions:**

* **Trie Initialization (`CreateTrie`, `GetProperty`):** The presence of `UCPTrie` and `kSerializedCharacterData` strongly implies pre-computed character properties stored in a trie data structure for efficient lookup. This is a common optimization technique for character property checks. The `GetProperty` function acts as a fast accessor.
* **Unicode Sets (`ApplyPatternAndFreezeIfEmpty`):**  This function uses ICU's `UnicodeSet`. The name suggests it initializes a set of characters based on a pattern and then makes it immutable. This is often used to define groups of characters for specific purposes (e.g., whitespace characters, word separators).
* **Individual Property Checks (`IsUprightInMixedVertical`, `IsCJKIdeographOrSymbolSlow`, etc.):**  A large portion of the file consists of functions that check specific character properties. The "Slow" suffix on some (like `IsCJKIdeographOrSymbolSlow`) is a hint that there might be a faster path available elsewhere, or that this particular check involves more computation. These functions frequently use `u_getIntPropertyValue` or the `GetProperty` helper function.
* **Expansion Opportunity Counting (`ExpansionOpportunityCount`):** These functions seem related to text layout and justification. They count places where whitespace or certain character types (like CJK ideographs) allow for expanding text. The distinction between `LChar` and `UChar` versions indicates handling of both ASCII and Unicode characters.
* **Text Decoration and Emphasis (`CanTextDecorationSkipInk`, `CanReceiveTextEmphasis`):** These functions relate to visual rendering. They determine whether text decorations (like underlines) should skip certain characters or if characters are suitable for emphasis marks.
* **Emoji and Script Functions (`IsEmojiTagSequence`, `IsExtendedPictographic`, `IsCommonOrInheritedScript`, etc.):** These functions indicate support for modern text features like emojis and script identification, which are important for correct rendering and language handling.
* **MathML Related Function (`IsVerticalMathCharacter`):**  The name and the internal `stretchy_operator_with_inline_axis` array point to specific handling of mathematical characters in the context of MathML (Mathematical Markup Language).

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:**  Character properties directly influence how JavaScript can manipulate and interpret text. For instance, `isWhitespace()` in JavaScript maps to the underlying character properties defined here. String manipulation methods also rely on understanding character boundaries and categories.
* **HTML:**  HTML rendering relies heavily on correct character handling. The way text wraps, line breaks, and is justified depends on these properties. Custom element names, as checked by `IsPotentialCustomElementNameChar`, are defined in HTML specifications.
* **CSS:** CSS properties like `text-decoration`, `text-emphasis`, `white-space`, and font selection are deeply connected to character properties. `CanTextDecorationSkipInk` directly relates to how underlines are rendered. The handling of CJK characters affects line breaking and justification, which are controlled by CSS.

**4. Logical Reasoning and Examples:**

* **Assumption:** The `GetProperty` function is faster than direct calls to ICU because it uses a pre-computed trie.
* **Input (to `IsCJKIdeographOrSymbolSlow`):** A Unicode code point like 0x4E00 (CJK Unified Ideograph-4E00, 一).
* **Output:** `true`.
* **Input:** A Unicode code point like 0x0041 (Latin capital letter A).
* **Output:** `false`.
* **Input (to `ExpansionOpportunityCount` with LTR direction):**  The string "hello world".
* **Output:** `count = 1`, `is_after_expansion = true` (after the space).
* **Input (to `ExpansionOpportunityCount` with RTL direction):** The string "world hello".
* **Output:** `count = 1`, `is_after_expansion = true` (after the space).

**5. Common User/Programming Errors:**

* **Incorrectly assuming ASCII-only:**  Forgetting that many characters are outside the ASCII range can lead to incorrect string length calculations or character processing.
* **Locale-insensitive operations:** Assuming that all whitespace is the same or that all punctuation behaves identically across languages can cause bugs. The file implicitly handles these differences through Unicode properties.
* **Misinterpreting "Slow" functions:**  Calling "Slow" functions repeatedly in performance-critical sections could be a mistake if a faster alternative exists or if the results can be cached.
* **Not handling surrogate pairs:** When dealing with characters outside the basic multilingual plane (BMP), developers need to correctly handle surrogate pairs (as seen in the `ExpansionOpportunityCount` functions).

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on individual functions. Realizing the overarching theme of "character properties" and how they relate to rendering and web standards helped to organize the analysis better.
* I also initially missed the significance of the "Slow" suffix. Recognizing this as a potential performance indicator added another layer to the understanding.
* Connecting the code to specific web technologies (HTML, CSS, JavaScript) required recalling how these technologies interact with text and character encoding. This involved thinking beyond just the code itself.

By following these steps, combining code analysis with knowledge of web technologies and potential pitfalls, a comprehensive understanding of the `character.cc` file can be achieved.
这个 `character.cc` 文件是 Chromium Blink 引擎中负责处理字符相关功能的源代码文件。它提供了一系列静态方法，用于判断和操作 Unicode 字符的各种属性。

以下是该文件的主要功能：

**1. 字符属性查询:**

* **基本属性:**  它提供了高效的方法来查询字符的基本属性，例如是否是空格、是否是 CJK 表意符号或符号、是否是潜在的自定义元素名称字符、是否是双向控制字符、是否是韩文等。这些属性数据很可能来源于 ICU (International Components for Unicode) 库。
* **韩文排版微调 (Han Kerning):**  提供方法来判断字符是否属于韩文排版微调的开放或闭合类型字符。这用于优化韩文文本的渲染效果。
* **可跳过墨迹的文本装饰:** 判断字符是否可以被文本装饰（如下划线）跳过，例如空格或某些标点符号。
* **可接收文本强调:** 判断字符是否适合添加文本强调符号（例如着重号）。
* **Emoji 相关:** 判断字符是否是 Emoji 标签序列的一部分、是否是扩展的图形符号、是否是 Emoji 组件、是否可能是 Emoji 展示形式。
* **脚本 (Script):** 判断字符是否属于通用或继承的脚本，是否拥有明确的脚本。
* **其他属性:**  是否是私有使用字符、是否是非字符 (non-character)。

**2. 文本处理相关:**

* **扩展机会计数 (Expansion Opportunity Count):**  计算在给定字符序列中，可以进行文本扩展（例如空格增加）的位置数量。它会根据文本方向 (LTR 或 RTL) 以及字符的属性（例如空格、CJK 字符）进行不同的计算。

**3. 特殊字符判断:**

* **垂直排版相关:** 判断字符是否是用于垂直排版的数学字符。

**与 JavaScript, HTML, CSS 的关系：**

该文件提供的功能是 Blink 渲染引擎的基础，直接或间接地影响着 JavaScript, HTML 和 CSS 的行为和渲染结果。

**JavaScript:**

* **字符串操作:** JavaScript 中的字符串操作（例如 `trim()`, `split()`, 正则表达式匹配）在底层可能依赖于这些字符属性判断。例如，JavaScript 的 `isWhitespace()` 方法的实现就可能使用类似 `TreatAsSpace()` 的逻辑。
* **文本处理 API:**  JavaScript 的文本处理 API，例如 `Intl` 对象，会使用 ICU 库提供的更丰富的国际化功能，而 `character.cc` 则是 Blink 对 ICU 某些功能的封装和使用。

**HTML:**

* **自定义元素名称:** `IsPotentialCustomElementNameChar()` 用于验证 HTML 自定义元素的名称是否符合规范。
    * **假设输入:**  字符 'a', '_', '-'
    * **输出:** `true`
    * **假设输入:** 字符 ' ', '$', '0' (作为首字符)
    * **输出:** `false`
* **文本渲染:**  字符属性直接影响文本在网页上的渲染方式，包括换行、空格处理、连字等等。例如，`ExpansionOpportunityCount` 的结果会影响文本在容器中的对齐和分布。
* **Emoji 展示:**  `IsEmojiTagSequence`, `IsExtendedPictographic`, `MaybeEmojiPresentation` 等方法确保 Emoji 能够被正确识别和渲染。

**CSS:**

* **`text-decoration` 属性:** `CanTextDecorationSkipInk()` 的结果决定了下划线、删除线等文本装饰是否会跳过某些字符。例如，我们通常不希望下划线穿过空格。
    * **例子:**  在 CSS 中设置 `text-decoration: underline`，如果遇到空格，`CanTextDecorationSkipInk(' ')` 返回 `true`，则下划线不会穿过空格。
* **`text-emphasis` 属性:** `CanReceiveTextEmphasis()` 决定了哪些字符可以添加着重号。
    * **例子:** 在 CSS 中设置 `text-emphasis-style: filled circle`，`CanReceiveTextEmphasis()` 为 `true` 的字符（例如汉字、字母）会被添加着重号，而空格等则不会。
* **`white-space` 属性:**  `TreatAsSpace()` 等方法与 CSS 的 `white-space` 属性的处理相关，例如 `white-space: pre-wrap` 如何处理空格和换行符。
* **字体选择和渲染:** 字符的脚本属性 (`IsCommonOrInheritedScript`, `HasDefiniteScript`) 可以帮助浏览器选择合适的字体进行渲染。
* **垂直排版:** `IsVerticalMathCharacter()` 这样的方法与 CSS 的垂直排版特性（例如 `writing-mode: vertical-rl`) 有关。

**逻辑推理的例子:**

假设我们需要实现一个简单的功能，判断一个字符串是否只包含空格字符。我们可以基于 `TreatAsSpace()` 方法进行推理：

* **假设输入:**  字符串 "  \t\n" (包含空格、制表符、换行符)
* **逻辑:** 遍历字符串中的每个字符，调用 `Character::TreatAsSpace()` 判断是否为空格。如果所有字符都返回 `true`，则字符串只包含空格字符。
* **输出:** `true`

* **假设输入:** 字符串 " hello "
* **逻辑:**  遍历字符串，当遇到 'h' 时，`Character::TreatAsSpace('h')` 返回 `false`。
* **输出:** `false`

**用户或编程常见的使用错误:**

* **假设所有空格都是一样的:** 不同的 Unicode 空格字符 (例如 `&nbsp;`) 在渲染和处理上可能有所不同。直接使用 ASCII 空格的判断可能无法覆盖所有情况。`TreatAsSpace()` 这样的方法考虑了更广泛的空格字符。
* **错误地计算字符串长度:**  一些 Unicode 字符使用多个代码单元 (例如 surrogate pairs)。简单地使用字符串的 `length` 属性可能无法得到正确的字符数量。Blink 内部的文本处理会考虑这些情况。
* **不理解双向文本 (BiDi):**  对于包含从右向左书写文字的文本，简单地从左到右处理字符可能会导致渲染错误。`IsBidiControl()` 这样的方法用于识别影响文本方向的字符。
* **在性能敏感的代码中过度使用“Slow”方法:**  文件名或方法名中带有 "Slow" 通常意味着该操作可能相对耗时。如果在循环或频繁调用的代码中使用这些方法，可能会影响性能。开发者应该尽量使用更高效的替代方案或缓存结果。

总而言之，`character.cc` 是 Blink 引擎中一个核心的底层文件，它提供了对 Unicode 字符属性进行高效查询和判断的基础设施，这些功能对于正确渲染和处理网页上的文本至关重要，并直接或间接地影响着 JavaScript, HTML 和 CSS 的行为。

### 提示词
```
这是目录为blink/renderer/platform/text/character.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/character.h"

#include <unicode/uchar.h>
#include <unicode/ucptrie.h>
#include <unicode/uobject.h>
#include <unicode/uscript.h>

#include <algorithm>

#include "base/synchronization/lock.h"
#include "third_party/blink/renderer/platform/text/character_property_data.h"
#include "third_party/blink/renderer/platform/text/icu_error.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

namespace {

UCPTrie* CreateTrie() {
  // Create a Trie from the value array.
  ICUError error;
  UCPTrie* trie = ucptrie_openFromBinary(
      UCPTrieType::UCPTRIE_TYPE_FAST, UCPTrieValueWidth::UCPTRIE_VALUE_BITS_16,
      kSerializedCharacterData, kSerializedCharacterDataSize, nullptr, &error);
  DCHECK_EQ(error, U_ZERO_ERROR);
  return trie;
}

unsigned GetProperty(UChar32 c, CharacterProperty property) {
  static const UCPTrie* trie = CreateTrie();
  return UCPTRIE_FAST_GET(trie, UCPTRIE_16, c) &
         static_cast<CharacterPropertyType>(property);
}

base::Lock& GetFreezePatternLock() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(base::Lock, lock, ());
  return lock;
}

}  // namespace

void Character::ApplyPatternAndFreezeIfEmpty(icu::UnicodeSet* unicodeSet,
                                             const char* pattern) {
  base::AutoLock locker(GetFreezePatternLock());
  if (!unicodeSet->isEmpty()) {
    return;
  }
  blink::ICUError err;
  // Use ICU's invariant-character initialization method.
  unicodeSet->applyPattern(icu::UnicodeString(pattern, -1, US_INV), err);
  unicodeSet->freeze();
  DCHECK_EQ(err, U_ZERO_ERROR);
}

bool Character::IsUprightInMixedVertical(UChar32 character) {
  return u_getIntPropertyValue(character,
                               UProperty::UCHAR_VERTICAL_ORIENTATION) !=
         UVerticalOrientation::U_VO_ROTATED;
}

bool Character::IsCJKIdeographOrSymbolSlow(UChar32 c) {
  return GetProperty(c, CharacterProperty::kIsCJKIdeographOrSymbol);
}

bool Character::IsPotentialCustomElementNameChar(UChar32 character) {
  return GetProperty(character,
                     CharacterProperty::kIsPotentialCustomElementNameChar);
}

bool Character::IsBidiControl(UChar32 character) {
  return GetProperty(character, CharacterProperty::kIsBidiControl);
}

bool Character::IsHangulSlow(UChar32 character) {
  return GetProperty(character, CharacterProperty::kIsHangul);
}

HanKerningCharType Character::GetHanKerningCharType(UChar32 character) {
  return static_cast<HanKerningCharType>(
      GetProperty(character, CharacterProperty::kHanKerningShiftedMask) >>
      static_cast<unsigned>(CharacterProperty::kHanKerningShift));
}

bool Character::MaybeHanKerningOpenSlow(UChar32 ch) {
  // See `HanKerning::GetCharType`.
  const HanKerningCharType type = Character::GetHanKerningCharType(ch);
  return type == HanKerningCharType::kOpen ||
         type == HanKerningCharType::kOpenQuote;
}

bool Character::MaybeHanKerningCloseSlow(UChar32 ch) {
  // See `HanKerning::GetCharType`.
  const HanKerningCharType type = Character::GetHanKerningCharType(ch);
  return type == HanKerningCharType::kClose ||
         type == HanKerningCharType::kCloseQuote;
}

unsigned Character::ExpansionOpportunityCount(
    base::span<const LChar> characters,
    TextDirection direction,
    bool& is_after_expansion) {
  unsigned count = 0;
  if (direction == TextDirection::kLtr) {
    for (size_t i = 0; i < characters.size(); ++i) {
      if (TreatAsSpace(characters[i])) {
        count++;
        is_after_expansion = true;
      } else {
        is_after_expansion = false;
      }
    }
  } else {
    for (size_t i = characters.size(); i > 0; --i) {
      if (TreatAsSpace(characters[i - 1])) {
        count++;
        is_after_expansion = true;
      } else {
        is_after_expansion = false;
      }
    }
  }

  return count;
}

unsigned Character::ExpansionOpportunityCount(
    base::span<const UChar> characters,
    TextDirection direction,
    bool& is_after_expansion) {
  unsigned count = 0;
  if (direction == TextDirection::kLtr) {
    for (size_t i = 0; i < characters.size(); ++i) {
      UChar32 character = characters[i];
      if (TreatAsSpace(character)) {
        count++;
        is_after_expansion = true;
        continue;
      }
      if (U16_IS_LEAD(character) && i + 1 < characters.size() &&
          U16_IS_TRAIL(characters[i + 1])) {
        character = U16_GET_SUPPLEMENTARY(character, characters[i + 1]);
        i++;
      }
      if (IsCJKIdeographOrSymbol(character)) {
        if (!is_after_expansion)
          count++;
        count++;
        is_after_expansion = true;
        continue;
      } else if (!IsDefaultIgnorable(character)) {
        is_after_expansion = false;
      }
    }
  } else {
    for (size_t i = characters.size(); i > 0; --i) {
      UChar32 character = characters[i - 1];
      if (TreatAsSpace(character)) {
        count++;
        is_after_expansion = true;
        continue;
      }
      if (U16_IS_TRAIL(character) && i > 1 && U16_IS_LEAD(characters[i - 2])) {
        character = U16_GET_SUPPLEMENTARY(characters[i - 2], character);
        i--;
      }
      if (IsCJKIdeographOrSymbol(character)) {
        if (!is_after_expansion)
          count++;
        count++;
        is_after_expansion = true;
        continue;
      } else if (!IsDefaultIgnorable(character)) {
        is_after_expansion = false;
      }
    }
  }
  return count;
}

bool Character::CanTextDecorationSkipInk(UChar32 codepoint) {
  if (codepoint == kSolidusCharacter || codepoint == kReverseSolidusCharacter ||
      codepoint == kLowLineCharacter)
    return false;

  if (Character::IsCJKIdeographOrSymbol(codepoint))
    return false;

  UBlockCode block = ublock_getCode(codepoint);
  switch (block) {
    // These blocks contain CJK characters we don't want to skip ink, but are
    // not ideograph that IsCJKIdeographOrSymbol() does not cover.
    case UBLOCK_HANGUL_JAMO:
    case UBLOCK_HANGUL_COMPATIBILITY_JAMO:
    case UBLOCK_HANGUL_SYLLABLES:
    case UBLOCK_HANGUL_JAMO_EXTENDED_A:
    case UBLOCK_HANGUL_JAMO_EXTENDED_B:
    case UBLOCK_LINEAR_B_IDEOGRAMS:
      return false;
    default:
      return true;
  }
}

bool Character::CanReceiveTextEmphasis(UChar32 c) {
  WTF::unicode::CharCategory category = WTF::unicode::Category(c);
  if (category &
      (WTF::unicode::kSeparator_Space | WTF::unicode::kSeparator_Line |
       WTF::unicode::kSeparator_Paragraph | WTF::unicode::kOther_NotAssigned |
       WTF::unicode::kOther_Control | WTF::unicode::kOther_Format))
    return false;

  // Additional word-separator characters listed in CSS Text Level 3 Editor's
  // Draft 3 November 2010.
  if (c == kEthiopicWordspaceCharacter ||
      c == kAegeanWordSeparatorLineCharacter ||
      c == kAegeanWordSeparatorDotCharacter ||
      c == kUgariticWordDividerCharacter ||
      c == kTibetanMarkIntersyllabicTshegCharacter ||
      c == kTibetanMarkDelimiterTshegBstarCharacter)
    return false;

  return true;
}

bool Character::IsEmojiTagSequence(UChar32 c) {
  // http://www.unicode.org/reports/tr51/proposed.html#valid-emoji-tag-sequences
  return (c >= kTagDigitZero && c <= kTagDigitNine) ||
         (c >= kTagLatinSmallLetterA && c <= kTagLatinSmallLetterZ);
}

bool Character::IsExtendedPictographic(UChar32 c) {
  return u_hasBinaryProperty(c, UCHAR_EXTENDED_PICTOGRAPHIC);
}

bool Character::IsEmojiComponent(UChar32 c) {
  return u_hasBinaryProperty(c, UCHAR_EMOJI_COMPONENT);
}

bool Character::MaybeEmojiPresentation(UChar32 c) {
  return c == kZeroWidthJoinerCharacter || c == 0x00A9 /* copyright sign */ ||
         c == 0x00AE /* registered sign */ || IsEmojiKeycapBase(c) ||
         IsInRange(c, 0x203C, 0x2B55) || c == kVariationSelector15Character ||
         c == 0x3030 || c == 0x303D || c == 0x3297 || c == 0x3299 ||
         c == kVariationSelector16Character || c >= 65536;
}

bool Character::IsCommonOrInheritedScript(UChar32 character) {
  ICUError status;
  UScriptCode script = uscript_getScript(character, &status);
  return U_SUCCESS(status) &&
         (script == USCRIPT_COMMON || script == USCRIPT_INHERITED);
}

bool Character::IsPrivateUse(UChar32 character) {
  return WTF::unicode::Category(character) & WTF::unicode::kOther_PrivateUse;
}

bool Character::IsNonCharacter(UChar32 character) {
  return U_IS_UNICODE_NONCHAR(character);
}

bool Character::HasDefiniteScript(UChar32 character) {
  ICUError err;
  UScriptCode hint_char_script = uscript_getScript(character, &err);
  if (!U_SUCCESS(err))
    return false;
  return hint_char_script != USCRIPT_INHERITED &&
         hint_char_script != USCRIPT_COMMON;
}

// https://w3c.github.io/mathml-core/#stretchy-operator-axis
static const UChar stretchy_operator_with_inline_axis[]{
    0x003D, 0x005E, 0x005F, 0x007E, 0x00AF, 0x02C6, 0x02C7, 0x02C9, 0x02CD,
    0x02DC, 0x02F7, 0x0302, 0x0332, 0x203E, 0x20D0, 0x20D1, 0x20D6, 0x20D7,
    0x20E1, 0x2190, 0x2192, 0x2194, 0x2198, 0x2199, 0x219C, 0x219D, 0x219E,
    0x21A0, 0x21A2, 0x21A3, 0x21A4, 0x21A6, 0x21A9, 0x21AA, 0x21AB, 0x21AC,
    0x21AD, 0x21B4, 0x21B9, 0x21BC, 0x21BD, 0x21C0, 0x21C1, 0x21C4, 0x21C6,
    0x21C7, 0x21C9, 0x21CB, 0x21CC, 0x21D0, 0x21D2, 0x21D4, 0x21DA, 0x21DB,
    0x21DC, 0x21DD, 0x21E0, 0x21E2, 0x21E4, 0x21E5, 0x21E6, 0x21E8, 0x21F0,
    0x21F6, 0x21FD, 0x21FE, 0x21FF, 0x23B4, 0x23B5, 0x23DC, 0x23DD, 0x23DE,
    0x23DF, 0x23E0, 0x23E1, 0x2500, 0x27F5, 0x27F6, 0x27F7, 0x27F8, 0x27F9,
    0x27FA, 0x27FB, 0x27FC, 0x27FD, 0x27FE, 0x27FF, 0x290C, 0x290D, 0x290E,
    0x290F, 0x2910, 0x294E, 0x2950, 0x2952, 0x2953, 0x2956, 0x2957, 0x295A,
    0x295B, 0x295E, 0x295F, 0x2B45, 0x2B46, 0xFE35, 0xFE36, 0xFE37, 0xFE38};

bool Character::IsVerticalMathCharacter(UChar32 text_content) {
  return text_content != kArabicMathematicalOperatorMeemWithHahWithTatweel &&
         text_content != kArabicMathematicalOperatorHahWithDal &&
         !std::binary_search(stretchy_operator_with_inline_axis,
                             stretchy_operator_with_inline_axis +
                                 std::size(stretchy_operator_with_inline_axis),
                             text_content);
}

}  // namespace blink
```
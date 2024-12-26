Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the given C++ test file (`unicode_utilities_test.cc`) within the Chromium Blink engine. The request also specifically asks about its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples (with input/output), and common user/programming errors.

**2. Identifying the Core Functionality:**

The filename itself (`unicode_utilities_test.cc`) strongly suggests that this file tests utilities related to Unicode handling. Skimming the code confirms this. It includes headers like `unicode/uchar.h` and definitions for functions like `IsSeparator`, `IsKanaLetter`, `ContainsKanaLetters`, `FoldQuoteMarksAndSoftHyphens`, `CheckOnlyKanaLettersInStrings`, and `CheckKanaStringsEqual`. These function names clearly indicate Unicode-related operations.

**3. Analyzing Each Test Case:**

The file is structured as a series of `TEST` macros, which is standard practice in Google Test. The next step is to examine each test case individually to understand what specific functionality it's verifying.

*   **`Separators`:** This test focuses on the `IsSeparator` function. It uses a static array `kLatinSeparatorTable` to predefine the expected behavior for Latin characters and then iterates through them, comparing the function's output to the table. It also uses `u_enumCharTypes` to test separator behavior across broader Unicode ranges.
*   **`KanaLetters`:** This test checks the `IsKanaLetter` function by iterating through Unicode ranges known to contain Hiragana and Katakana characters.
*   **`ContainsKanaLetters`:** This test verifies the `ContainsKanaLetters` function. It constructs strings with and without Kana characters and asserts the function's correctness.
*   **`FoldQuoteMarkOrSoftHyphenTest`:** This test targets the `FoldQuoteMarksAndSoftHyphens` function. It provides a set of quotation marks and soft hyphens and checks if the function correctly replaces them with standard equivalents.
*   **`OnlyKanaLettersEqualityTest`:** This test scrutinizes the `CheckOnlyKanaLettersInStrings` function. It tests cases with only non-Kana characters, mixes of Kana and non-Kana, and variations in voiced Kana characters (using dakuten and handakuten).
*   **`StringsWithKanaLettersTest`:** This test examines the `CheckKanaStringsEqual` function. It covers scenarios with purely non-Kana strings, strings with Kana, and the impact of different sound marks on Kana characters.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is a crucial part of the request. The key is to think about *where* and *how* Unicode handling is relevant in web technologies.

*   **JavaScript:** JavaScript heavily relies on Unicode for string manipulation. The tested utilities likely play a role in internal string comparisons, text processing, and potentially even in areas like regular expression matching or internationalization features.
*   **HTML:** HTML documents are encoded in Unicode (typically UTF-8). The correct interpretation and rendering of characters, including separators and special characters, depend on proper Unicode handling. The tested functions could be used when parsing HTML content or when performing operations on text within the DOM.
*   **CSS:** CSS deals with text rendering, and it needs to understand character boundaries and properties related to whitespace and other separators. The `IsSeparator` function could be used internally by the rendering engine to determine how to lay out text.

**5. Providing Examples (Input/Output, User Errors):**

For each function, try to come up with simple, illustrative examples.

*   **Input/Output:** For functions like `IsSeparator` or `IsKanaLetter`, the input is a single Unicode code point, and the output is a boolean. For string-based functions, the input is a string, and the output can be a boolean or a modified string.
*   **User/Programming Errors:** Think about common mistakes developers might make when working with Unicode. Mixing up different types of quotation marks, not handling soft hyphens correctly, or assuming ASCII-only input are all potential pitfalls. Focus on how the tested utilities might help *prevent* or mitigate these errors within the browser engine.

**6. Structuring the Answer:**

Organize the findings logically. Start with a summary of the file's purpose, then detail the functionality of each test case. Follow this with the connections to web technologies, using concrete examples. Finally, address logical reasoning and potential errors.

**7. Refining the Language:**

Use clear and concise language. Avoid overly technical jargon where possible, or explain it briefly. Ensure the examples are easy to understand. For instance, instead of just saying "Unicode property," explain what that property represents (e.g., "whether a character is considered a separator").

**Self-Correction/Refinement during the process:**

*   **Initial thought:** "This file just tests some random Unicode functions."
*   **Correction:**  Realizing the file is part of the *Blink* engine makes it clear these functions are crucial for web browser functionality, specifically how the browser handles and renders text.
*   **Initial thought:** "The connection to web technologies is too abstract."
*   **Refinement:** Focusing on *specific scenarios* like parsing HTML, rendering text in CSS, and manipulating strings in JavaScript makes the connections more concrete. Thinking about the *purpose* of each function in the context of these technologies helps.
*   **Initial thought:**  "Just list the function names and say they relate to Unicode."
*   **Refinement:**  Providing *examples* of how these functions might be used and what potential errors they address makes the explanation much more valuable.

By following this systematic approach, we can effectively analyze the C++ test file and provide a comprehensive and informative answer.
这个文件 `unicode_utilities_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `unicode_utilities.h` 头文件中定义的 Unicode 相关实用工具函数的单元测试文件。

**功能概览:**

该文件通过编写一系列的测试用例，来验证 `unicode_utilities.h` 中实现的各种 Unicode 相关功能的正确性。这些功能通常涉及到对 Unicode 字符的属性判断、转换和比较等操作。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

Blink 引擎负责将 HTML、CSS 和 JavaScript 代码渲染成用户可见的网页。`unicode_utilities.h` 中定义的工具函数在处理网页文本时扮演着重要的角色。以下是一些可能的关联和举例：

1. **文本分词和断行 (HTML, CSS):**  `IsSeparator` 函数用于判断一个字符是否是分隔符（例如空格、标点符号等）。这对于文本的自动换行、分词处理至关重要。浏览器需要知道在哪里可以安全地断开一行文本，以适应不同的屏幕尺寸和布局。
    *   **假设输入:**  一个包含空格、逗号和句号的字符串 "Hello, world."
    *   **输出:** `IsSeparator(' ')` 返回 `true`， `IsSeparator(',')` 返回 `true`， `IsSeparator('.')` 返回 `true`， `IsSeparator('H')` 返回 `false`。
    *   **例子:** 当浏览器渲染 HTML 中的 `<p>Hello, world.</p>` 时，会使用类似 `IsSeparator` 的函数来确定可以在哪里换行。CSS 的 `word-break` 和 `overflow-wrap` 属性也会间接依赖于这种字符分类。

2. **Kana 字符处理 (HTML, JavaScript):** `IsKanaLetter` 和 `ContainsKanaLetters` 函数用于判断一个字符或字符串是否包含日语假名（平假名和片假名）。这在处理包含日文的网页时非常重要。
    *   **假设输入:**
        *   `IsKanaLetter(0x3041)` (ぁ - Hiragana letter A)
        *   `IsKanaLetter(0x30A1)` (ァ - Katakana letter A)
        *   `IsKanaLetter('A')`
        *   `ContainsKanaLetters("こんにちは")`
        *   `ContainsKanaLetters("hello")`
    *   **输出:**
        *   `IsKanaLetter(0x3041)` 返回 `true`
        *   `IsKanaLetter(0x30A1)` 返回 `true`
        *   `IsKanaLetter('A')` 返回 `false`
        *   `ContainsKanaLetters("こんにちは")` 返回 `true`
        *   `ContainsKanaLetters("hello")` 返回 `false`
    *   **例子:**  JavaScript 可以使用正则表达式或者自定义逻辑来检测用户输入的文本是否包含日文假名。Blink 内部可能使用这些函数来优化日文文本的渲染或进行特定的文本处理。

3. **引号和软连字符的标准化 (HTML, JavaScript):** `FoldQuoteMarksAndSoftHyphens` 函数用于将各种类型的引号（例如左右双引号、单引号）和软连字符统一转换为标准形式。
    *   **假设输入:** 包含不同类型引号和软连字符的字符串： "“Hello”’world’\u00AD"
    *   **输出:**  将字符串中的 `“` 和 `”` 转换为 `"`，将 `‘` 和 `’` 转换为 `'`，将软连字符 `\u00AD` 移除或替换为空字符串 (根据具体实现)。
    *   **例子:** 当用户从网页复制文本时，不同的网站可能会使用不同的引号。浏览器在内部处理或传递给 JavaScript 之前，可能会进行标准化，以避免出现不一致性或解析错误。

4. **Kana 字符串比较 (HTML, JavaScript):** `CheckOnlyKanaLettersInStrings` 和 `CheckKanaStringsEqual` 函数用于比较仅包含假名的字符串或包含假名的字符串是否相等，并考虑了浊音和半浊音符号的影响。
    *   **假设输入:**
        *   `CheckOnlyKanaLettersInStrings("か", "が")`
        *   `CheckKanaStringsEqual("か", "が")`
        *   `CheckKanaStringsEqual("か", "カ")`
        *   `CheckKanaStringsEqual("おはよう", "おはよう")`
        *   `CheckKanaStringsEqual("おはよう", "こんにちは")`
    *   **输出:**
        *   `CheckOnlyKanaLettersInStrings("か", "が")` 返回 `false` (因为浊音不同)
        *   `CheckKanaStringsEqual("か", "が")` 返回 `false` (即使是相同的基本字符，浊音符号也使它们不同)
        *   `CheckKanaStringsEqual("か", "カ")` 返回 `false` (平假名和片假名不同)
        *   `CheckKanaStringsEqual("おはよう", "おはよう")` 返回 `true`
        *   `CheckKanaStringsEqual("おはよう", "こんにちは")` 返回 `false`
    *   **例子:** JavaScript 中可能需要比较用户输入的日文文本，例如在搜索或表单验证中。Blink 内部可能使用这些函数来比较资源或进行文本匹配。

**逻辑推理的假设输入与输出:**

这里主要体现在每个 `TEST` 宏内部的断言 (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`)。  每个测试用例都针对特定的函数和输入，并验证其输出是否符合预期。

例如，在 `Separators` 测试中：

*   **假设输入:** 遍历 ASCII 字符 (0 到 255)。
*   **逻辑推理:** 对于每个字符，调用 `IsSeparator` 函数，并将其结果与预定义的 `kLatinSeparatorTable` 中的值进行比较。
*   **预期输出:** `IsSeparator(character)` 的返回值应该与 `kLatinSeparatorTable[character]` 的值相等。

在 `KanaLetters` 测试中：

*   **假设输入:** 遍历平假名 Unicode 范围 (0x3041 到 0x3096)。
*   **逻辑推理:** 对于此范围内的每个字符，调用 `IsKanaLetter` 函数。
*   **预期输出:** `IsKanaLetter(character)` 应该返回 `true`。

**涉及用户或编程常见的使用错误:**

虽然这个测试文件本身不直接涉及用户交互，但它测试的底层功能与用户和开发者在使用 Web 技术时可能遇到的问题息息相关。

1. **不正确的字符判断:**  开发者可能错误地判断一个字符是否是分隔符，导致文本处理逻辑错误，例如在 JavaScript 中手动进行分词时。`IsSeparator` 函数的正确性保证了 Blink 内部处理的准确性。

2. **Kana 字符处理不当:**  开发者可能在处理日文文本时，没有考虑到平假名、片假名以及浊音、半浊音符号的区别，导致字符串比较或搜索结果不正确。`CheckOnlyKanaLettersInStrings` 和 `CheckKanaStringsEqual` 测试了 Blink 如何正确处理这些情况。
    *   **用户常见错误:** 用户在搜索时可能没有区分平假名和片假名，导致搜不到预期的结果。
    *   **编程常见错误:** 开发者在 JavaScript 中使用简单的字符串相等比较 (`===`) 来比较可能包含假名的字符串，而没有考虑到浊音等因素。

3. **引号和软连字符处理不一致:**  开发者可能在不同的场景下使用了不同类型的引号，或者没有正确处理软连字符，导致文本显示或处理上的不一致性。`FoldQuoteMarksAndSoftHyphens` 的测试确保了 Blink 能够对这些字符进行标准化处理，减少潜在的问题。
    *   **用户常见错误:** 用户复制粘贴的文本中可能包含非标准的引号，导致网页显示异常。
    *   **编程常见错误:** 开发者在处理用户输入时，没有对各种引号进行统一处理，导致数据存储或展示上的混乱。

**总结:**

`unicode_utilities_test.cc` 是 Blink 引擎中一个关键的测试文件，它确保了底层的 Unicode 处理功能的正确性。这些功能直接影响着浏览器如何解析、渲染和处理网页文本，与 JavaScript、HTML 和 CSS 的功能紧密相关。通过各种测试用例，它帮助避免了开发者和用户在使用 Web 技术时可能遇到的与 Unicode 相关的常见错误。

Prompt: 
```
这是目录为blink/renderer/platform/text/unicode_utilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (c) 2013 Yandex LLC. All rights reserved.
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
 *     * Neither the name of Yandex LLC nor the names of its
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

#include "third_party/blink/renderer/platform/text/unicode_utilities.h"

#include <unicode/uchar.h>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

static const UChar32 kMaxLatinCharCount = 256;

static bool g_is_test_first_and_last_chars_in_category_failed = false;
UBool U_CALLCONV TestFirstAndLastCharsInCategory(const void* context,
                                                 UChar32 start,
                                                 UChar32 limit,
                                                 UCharCategory type) {
  if (start >= kMaxLatinCharCount &&
      U_MASK(type) & (U_GC_P_MASK | U_GC_Z_MASK | U_GC_CF_MASK) &&
      (!IsSeparator(start) || !IsSeparator(limit - 1))) {
    g_is_test_first_and_last_chars_in_category_failed = true;

    // Break enumeration process
    return 0;
  }

  return 1;
}

TEST(UnicodeUtilitiesTest, Separators) {
  // clang-format off
  static constexpr auto kLatinSeparatorTable = std::to_array<uint8_t>({
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

  for (UChar32 character = 0; character < kMaxLatinCharCount; ++character) {
    EXPECT_EQ(IsSeparator(character),
              static_cast<bool>(kLatinSeparatorTable[character]));
  }

  g_is_test_first_and_last_chars_in_category_failed = false;
  u_enumCharTypes(&TestFirstAndLastCharsInCategory, nullptr);
  EXPECT_FALSE(g_is_test_first_and_last_chars_in_category_failed);
}

TEST(UnicodeUtilitiesTest, KanaLetters) {
  // Non Kana symbols
  for (UChar character = 0; character < 0x3041; ++character)
    EXPECT_FALSE(IsKanaLetter(character));

  // Hiragana letters.
  for (UChar character = 0x3041; character <= 0x3096; ++character)
    EXPECT_TRUE(IsKanaLetter(character));

  // Katakana letters.
  for (UChar character = 0x30A1; character <= 0x30FA; ++character)
    EXPECT_TRUE(IsKanaLetter(character));
}

TEST(UnicodeUtilitiesTest, ContainsKanaLetters) {
  // Non Kana symbols
  StringBuilder non_kana_string;
  for (UChar character = 0; character < 0x3041; ++character)
    non_kana_string.Append(character);
  EXPECT_FALSE(ContainsKanaLetters(non_kana_string.ToString()));

  // Hiragana letters.
  for (UChar character = 0x3041; character <= 0x3096; ++character) {
    StringBuilder str;
    str.Append(non_kana_string);
    str.Append(character);
    EXPECT_TRUE(ContainsKanaLetters(str.ToString()));
  }

  // Katakana letters.
  for (UChar character = 0x30A1; character <= 0x30FA; ++character) {
    StringBuilder str;
    str.Append(non_kana_string);
    str.Append(character);
    EXPECT_TRUE(ContainsKanaLetters(str.ToString()));
  }
}

TEST(UnicodeUtilitiesTest, FoldQuoteMarkOrSoftHyphenTest) {
  const UChar kCharactersToFold[] = {kHebrewPunctuationGershayimCharacter,
                                     kLeftDoubleQuotationMarkCharacter,
                                     kRightDoubleQuotationMarkCharacter,
                                     kHebrewPunctuationGereshCharacter,
                                     kLeftSingleQuotationMarkCharacter,
                                     kRightSingleQuotationMarkCharacter,
                                     kSoftHyphenCharacter};

  String string_to_fold{base::span(kCharactersToFold)};
  Vector<UChar> buffer;
  string_to_fold.AppendTo(buffer);

  FoldQuoteMarksAndSoftHyphens(string_to_fold);

  const String folded_string(base::span_from_cstring("\"\"\"\'\'\'\0"));
  ASSERT_EQ(std::size(kCharactersToFold), folded_string.length());
  EXPECT_EQ(string_to_fold, folded_string);

  FoldQuoteMarksAndSoftHyphens(base::span(buffer));
  EXPECT_EQ(String(buffer), folded_string);
}

TEST(UnicodeUtilitiesTest, OnlyKanaLettersEqualityTest) {
  const UChar kNonKanaString1[] = {'a', 'b', 'c', 'd'};
  const UChar kNonKanaString2[] = {'e', 'f', 'g'};

  // Check that non-Kana letters will be skipped.
  EXPECT_TRUE(CheckOnlyKanaLettersInStrings(base::span(kNonKanaString1),
                                            base::span(kNonKanaString2)));

  const UChar kKanaString[] = {'e', 'f', 'g', 0x3041};
  EXPECT_FALSE(CheckOnlyKanaLettersInStrings(base::span(kKanaString),
                                             base::span(kNonKanaString2)));

  // Compare with self.
  EXPECT_TRUE(CheckOnlyKanaLettersInStrings(base::span(kKanaString),
                                            base::span(kKanaString)));

  UChar voiced_kana_string1[] = {0x3042, 0x3099};
  UChar voiced_kana_string2[] = {0x3042, 0x309A};

  // Comparing strings with different sound marks should fail.
  EXPECT_FALSE(CheckOnlyKanaLettersInStrings(base::span(voiced_kana_string1),
                                             base::span(voiced_kana_string2)));

  // Now strings will be the same.
  voiced_kana_string2[1] = 0x3099;
  EXPECT_TRUE(CheckOnlyKanaLettersInStrings(base::span(voiced_kana_string1),
                                            base::span(voiced_kana_string2)));

  voiced_kana_string2[0] = 0x3043;
  EXPECT_FALSE(CheckOnlyKanaLettersInStrings(base::span(voiced_kana_string1),
                                             base::span(voiced_kana_string2)));
}

TEST(UnicodeUtilitiesTest, StringsWithKanaLettersTest) {
  const UChar kNonKanaString1[] = {'a', 'b', 'c'};
  const UChar kNonKanaString2[] = {'a', 'b', 'c'};

  // Check that non-Kana letters will be compared.
  EXPECT_TRUE(CheckKanaStringsEqual(base::span(kNonKanaString1),
                                    base::span(kNonKanaString2)));

  const UChar kKanaString[] = {'a', 'b', 'c', 0x3041};
  EXPECT_FALSE(CheckKanaStringsEqual(base::span(kKanaString),
                                     base::span(kNonKanaString2)));

  // Compare with self.
  EXPECT_TRUE(
      CheckKanaStringsEqual(base::span(kKanaString), base::span(kKanaString)));

  const UChar kKanaString2[] = {'x', 'y', 'z', 0x3041};
  // Comparing strings with different non-Kana letters should fail.
  EXPECT_FALSE(
      CheckKanaStringsEqual(base::span(kKanaString), base::span(kKanaString2)));

  const UChar kKanaString3[] = {'a', 'b', 'c', 0x3042, 0x3099, 'm', 'n', 'o'};
  // Check that non-Kana letters after Kana letters will be compared.
  EXPECT_TRUE(CheckKanaStringsEqual(base::span(kKanaString3),
                                    base::span(kKanaString3)));

  const UChar kKanaString4[] = {'a', 'b', 'c', 0x3042, 0x3099,
                                'm', 'n', 'o', 'p'};
  // And now comparing should fail.
  EXPECT_FALSE(CheckKanaStringsEqual(base::span(kKanaString3),
                                     base::span(kKanaString4)));

  UChar voiced_kana_string1[] = {0x3042, 0x3099};
  UChar voiced_kana_string2[] = {0x3042, 0x309A};

  // Comparing strings with different sound marks should fail.
  EXPECT_FALSE(CheckKanaStringsEqual(base::span(voiced_kana_string1),
                                     base::span(voiced_kana_string2)));

  // Now strings will be the same.
  voiced_kana_string2[1] = 0x3099;
  EXPECT_TRUE(CheckKanaStringsEqual(base::span(voiced_kana_string1),
                                    base::span(voiced_kana_string2)));

  voiced_kana_string2[0] = 0x3043;
  EXPECT_FALSE(CheckKanaStringsEqual(base::span(voiced_kana_string1),
                                     base::span(voiced_kana_string2)));
}

}  // namespace blink

"""

```
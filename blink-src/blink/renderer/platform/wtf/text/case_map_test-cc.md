Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Scan and Identification of Key Components:**

The first step is to quickly scan the code and identify the main elements. Keywords like `#include`, `namespace`, `struct`, `class`, `TEST_P`, `TEST`, `EXPECT_EQ`, `EXPECT_THAT`, and data structures like `std::vector` immediately stand out.

*   `#include`:  Indicates dependencies on other parts of the Chromium codebase and testing frameworks (gmock, gtest). The presence of `case_map.h` is crucial – this test file is specifically testing the functionality declared in that header.
*   `namespace WTF`:  This tells us the code belongs to the "Web Template Framework" within Chromium, which deals with fundamental utilities.
*   `struct CaseMapTestData`: This looks like a data structure holding inputs and expected outputs for the tests. The fields `source`, `locale`, `lower_expected`, `upper_expected`, `lower_map`, and `upper_map` give a good hint about what's being tested (case mapping with optional offset tracking).
*   `class CaseMapTest`: This is the core test fixture, using Google Test (`testing::Test`) and parameterized testing (`testing::WithParamInterface`).
*   `INSTANTIATE_TEST_SUITE_P`:  Confirms the use of parameterized testing with the data from `case_map_test_data`.
*   `TEST_P`:  Indicates parameterized tests, meaning each test case will run multiple times with different inputs from the `case_map_test_data`.
*   `TEST`:  Indicates standard non-parameterized tests.
*   `EXPECT_EQ`:  A Google Test assertion to check for equality.
*   `EXPECT_THAT`:  A more flexible Google Mock assertion, used here with `ElementsAreArray` to compare vectors.
*   `TextOffsetMap`: This is likely a class used to track how the length of the string changes during case conversion.

**2. Understanding the Core Functionality Being Tested:**

Based on the identified components, it's clear the file is testing the `CaseMap` class. The `ToLower` and `ToUpper` methods of this class are the primary targets. The presence of `locale` suggests that the case mapping is locale-aware (different languages have different casing rules).

**3. Analyzing the Test Data (`case_map_test_data`):**

Examining the individual entries in `case_map_test_data` provides concrete examples of the functionality being tested:

*   Empty strings, non-letters, and basic ASCII casing are the starting points.
*   The German "eszett" (`\u00DF`) example shows how uppercasing can *increase* the string length ("SS"). The associated `upper_map` indicates the offset change (one character becoming two).
*   Turkish/Azeri examples (`\u0130`, `I\u0307`) demonstrate locale-specific casing, where 'I' uppercases to dotted I, and dotted I lowercases to dotless i. The offset maps show length changes.
*   Lithuanian examples show cases where uppercasing can *decrease* length and lowercasing can *increase* length.
*   The `lower_map` and `upper_map` in these examples are crucial for understanding how the `TextOffsetMap` is used to track the changes in string length during case conversion.

**4. Analyzing the Test Cases (`TEST_P` and `TEST`):**

*   The `TEST_P` cases systematically test `ToLower` and `ToUpper` with and without the `TextOffsetMap`. The `EXPECT_EQ` checks if the converted string matches the expected output, and `EXPECT_THAT` verifies the correctness of the offset map. The `ToLower8Bit` and `ToUpper8Bit` cases specifically test the handling of 8-bit strings.
*   The `TEST` cases (`ToUpperLocale` and `ToLowerLocale`) test locale-sensitive case mapping with a larger set of locale variations. They use `std::to_array` and loops to iterate through different locales for the same input string. The data for these tests (`g_turkic_input`, `g_greek_input`, etc.) and the locale lists (`g_turkic_locales`, `g_non_turkic_locales`, etc.) are essential for understanding the scope of locale testing.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, the crucial step is to connect this low-level C++ code to higher-level web technologies.

*   **JavaScript:**  JavaScript's `String.prototype.toLowerCase()` and `String.prototype.toUpperCase()` are the most direct connections. The C++ `CaseMap` likely implements the underlying logic for these JavaScript functions within the Blink engine.
*   **HTML:** The `lang` attribute in HTML elements directly influences how text within that element is rendered, including case conversion if CSS styles are applied.
*   **CSS:** The `text-transform` property in CSS (`uppercase`, `lowercase`) relies on the underlying case mapping functionality. The `CaseMap` class is likely involved in the implementation of `text-transform`.

**6. Identifying Potential User/Programming Errors:**

Based on the test cases and the nature of locale-sensitive operations, potential errors become apparent:

*   **Incorrect Locale:**  Providing the wrong locale string can lead to unexpected case conversions (e.g., applying English casing rules to Turkish text).
*   **Assuming Simple 1:1 Mapping:**  Programmers might assume that uppercasing or lowercasing simply changes each character to its counterpart. The German "eszett" and the Turkish/Lithuanian examples demonstrate that this is not always the case. String length can change.
*   **Ignoring Locale:**  Forgetting to consider the locale when performing case-insensitive comparisons or data normalization can lead to bugs, especially when dealing with user-generated content from different regions.

**7. Formulating Assumptions, Inputs, and Outputs (Logical Reasoning):**

Based on the structure of the tests, we can infer the logic being tested:

*   **Assumption:** The `CaseMap` class correctly implements locale-aware case conversion.
*   **Input:** A string and an optional locale string.
*   **Output:** The lowercased or uppercased string, and optionally a `TextOffsetMap` detailing the changes in string length.

**Self-Correction/Refinement during the thought process:**

Initially, I might have just focused on the basic ASCII casing examples. However, recognizing the significance of the non-ASCII examples (German, Turkish, Lithuanian) and the `TextOffsetMap` is key to understanding the complexity and purpose of this code. The locale-specific tests further emphasize the importance of cultural considerations in text processing. It's important not to oversimplify the function of this code. The tests are designed to catch subtle edge cases.
这个文件 `case_map_test.cc` 是 Chromium Blink 引擎中 `wtf` (Web Template Framework) 库的一部分，专门用于测试 `CaseMap` 类的功能。`CaseMap` 类负责执行字符串的大小写转换，并且能够处理不同语言环境（locale）的特殊规则。

**功能列举:**

1. **测试基本的大小写转换:**  验证 `CaseMap` 类在没有指定 locale 的情况下，对 ASCII 字符进行正确的大小写转换。
2. **测试带 locale 的大小写转换:**  验证 `CaseMap` 类在指定 locale 的情况下，能够根据该 locale 的规则进行大小写转换。这包括处理诸如土耳其语、立陶宛语等特殊字符的大小写转换规则。
3. **测试大小写转换时的字符串长度变化:**  某些语言的字符在大小写转换时，其字符长度会发生变化（例如，德语的 "ß" 在大写时变为 "SS"）。这个测试文件会验证 `CaseMap` 能正确处理这种情况，并使用 `TextOffsetMap` 记录这种长度变化。
4. **测试 8 位字符串的大小写转换:**  验证 `CaseMap` 类能够正确处理 8 位编码的字符串的大小写转换。
5. **使用参数化测试:**  利用 Google Test 的参数化测试框架，使用 `case_map_test_data` 数组中的多组测试数据来全面覆盖 `CaseMap` 类的各种使用场景。

**与 JavaScript, HTML, CSS 的关系举例:**

`CaseMap` 类在 Blink 引擎中扮演着底层角色，为 JavaScript、HTML 和 CSS 中涉及到字符串大小写转换的功能提供支持。

*   **JavaScript:**
    *   **`String.prototype.toLowerCase()` 和 `String.prototype.toUpperCase()`:**  JavaScript 的这两个方法在底层很可能就是调用了 Blink 引擎中的相关大小写转换逻辑，而 `CaseMap` 类就可能是实现这些逻辑的关键部分。例如，当 JavaScript 代码执行 `str.toUpperCase()` 时，如果 `str` 包含德语的 "ß"，Blink 引擎会使用类似 `CaseMap` 的机制将其转换为 "SS"。
    *   **示例:**
        ```javascript
        const germanString = "Groß";
        const upperCaseString = germanString.toUpperCase(); // "GROSS"
        ```
        Blink 引擎在执行上述 JavaScript 代码时，会利用类似 `CaseMap` 的功能，识别出 "ß" 并根据 locale 规则将其转换为 "SS"。

*   **HTML:**
    *   **`lang` 属性:** HTML 的 `lang` 属性指定了元素的语言。浏览器在渲染页面时，可能会根据 `lang` 属性来应用特定的排版和文本处理规则，包括大小写转换。虽然 HTML 本身不直接进行大小写转换，但这个属性会影响到 CSS 和 JavaScript 中相关功能的行为。
    *   **示例:**
        ```html
        <p lang="tr">Büyük Harf</p>
        <script>
          const text = document.querySelector('p').textContent;
          console.log(text.toUpperCase()); // 在土耳其语环境下可能会输出 "BÜYÜK HARF"
        </script>
        ```
        如果 JavaScript 代码获取了带有 `lang="tr"` 的元素的文本内容并调用 `toUpperCase()`，Blink 引擎会考虑土耳其语的规则，例如将小写的 "i" 转换为大写的 "İ"。

*   **CSS:**
    *   **`text-transform` 属性:** CSS 的 `text-transform` 属性允许开发者控制文本的大小写，例如 `uppercase` 和 `lowercase`。Blink 引擎在渲染时，会使用类似 `CaseMap` 的功能来实现这些转换。
    *   **示例:**
        ```html
        <style>
          .uppercase {
            text-transform: uppercase;
          }
        </style>
        <p class="uppercase">klein</p>
        ```
        当浏览器渲染上述 HTML 时，会应用 `text-transform: uppercase` 规则，Blink 引擎会调用类似 `CaseMap` 的机制将 "klein" 转换为 "KLEIN"。如果文本包含特殊字符，例如土耳其语的 "ı"，则会根据当前的 locale 进行转换。

**逻辑推理的假设输入与输出:**

以下是一些基于 `case_map_test_data` 的逻辑推理示例：

**假设输入 1:**

*   `source`: "weiß"
*   `locale`: "de" (德国)

**预期输出 1:**

*   `lower_expected`: "weiß"
*   `upper_expected`: "WEISS"
*   `upper_map`: `{{2, 3}}`  (索引 2 的 "ß" 转换为索引 2 和 3 的 "SS")

**解释:**  根据德国的规则，小写的 "ß" 在转换为大写时会变成 "SS"，字符串长度增加。`upper_map` 记录了这种偏移。

**假设输入 2:**

*   `source`: "FILE"
*   `locale`: "tr" (土耳其)

**预期输出 2:**

*   `lower_expected`: "fıle"

**解释:** 在土耳其语中，大写的 "I" 对应的小写是 "ı" (点号在下的 i)。

**假设输入 3:**

*   `source`: "istanbul"
*   `locale`: "TR" (土耳其)

**预期输出 3:**

*   `upper_expected`: "İSTANBUL"

**解释:** 在土耳其语中，小写的 "i" 对应的大写是 "İ" (带点号的 I)。

**涉及用户或编程常见的使用错误举例:**

1. **忽略 locale:**  在需要进行本地化处理的场景下，没有指定正确的 locale 进行大小写转换。例如，在处理用户提交的用户名时，如果需要进行大小写不敏感的比较，但没有根据用户的语言环境进行转换，可能会导致比较结果不正确。

    ```javascript
    const input = "istanbul";
    const upperCaseEN = input.toUpperCase(); // "ISTANBUL"
    const upperCaseTR = input.toLocaleUpperCase('tr-TR'); // "İSTANBUL"

    if (upperCaseEN === "İSTANBUL") { // 错误：在非土耳其语环境下比较会失败
      console.log("Match!");
    }

    if (upperCaseTR === "İSTANBUL") { // 正确：使用土耳其语 locale 进行比较
      console.log("Match!");
    }
    ```

2. **假设大小写转换是简单的 1:1 映射:**  程序员可能会错误地认为每个字符都有唯一对应的大写或小写形式，并且转换不会改变字符串的长度。这在处理像德语的 "ß" 或其他特殊字符时会导致问题。

    ```javascript
    const germanWord = "weiß";
    const upper = germanWord.toUpperCase(); // "WEISS"
    console.log(upper.length); // 5，长度增加了

    // 错误地假设转换后长度不变
    if (germanWord.length === upper.length) {
      console.log("Lengths are the same"); // 不会输出
    }
    ```

3. **在不应该进行大小写转换的地方进行转换:**  有时，大小写转换可能会破坏数据的原始意义。例如，在处理某些 ID 或代码时，大小写可能是有意义的，不应该随意进行转换。

    ```javascript
    const productId = "ProductID123";
    const lowerCasedId = productId.toLowerCase(); // "productid123"

    // 如果后台系统区分大小写，则转换后的 ID 可能无法识别
    // 调用 API 时可能出错
    // fetch(`/api/products/${lowerCasedId}`);
    ```

总而言之，`case_map_test.cc` 文件通过一系列的测试用例，确保 Blink 引擎中的 `CaseMap` 类能够正确地执行各种场景下的大小写转换，特别是涉及到不同语言和字符长度变化的情况，这对于保证 Web 平台处理文本的正确性至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/case_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/wtf/text/case_map.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using testing::ElementsAreArray;

namespace WTF {

namespace {

String To8BitOrNull(const String& source) {
  if (source.IsNull() || source.Is8Bit())
    return source;
  if (!source.ContainsOnlyLatin1OrEmpty())
    return String();
  return String::Make8BitFrom16BitSource(source.Span16());
}

}  // namespace

static struct CaseMapTestData {
  const char16_t* source;
  const char* locale;
  const char16_t* lower_expected;
  const char16_t* upper_expected;
  std::vector<TextOffsetMap::Entry> lower_map = {};
  std::vector<TextOffsetMap::Entry> upper_map = {};
} case_map_test_data[] = {
    // Empty string.
    {nullptr, "", nullptr, nullptr},
    {u"", "", u"", u""},
    // Non-letters
    {u"123", "", u"123", u"123"},
    // ASCII lower/uppercases.
    {u"xyz", "", u"xyz", u"XYZ"},
    {u"XYZ", "", u"xyz", u"XYZ"},
    {u"Xyz", "", u"xyz", u"XYZ"},
    {u"xYz", "", u"xyz", u"XYZ"},
    // German eszett. Uppercasing makes the string longer.
    {u"\u00DF", "", u"\u00DF", u"SS", {}, {{1, 2}}},
    {u"\u00DFz", "", u"\u00DFz", u"SSZ", {}, {{1, 2}}},
    {u"x\u00DF", "", u"x\u00DF", u"XSS", {}, {{2, 3}}},
    {u"x\u00DFz", "", u"x\u00DFz", u"XSSZ", {}, {{2, 3}}},
    // Turkish/Azeri.
    {u"\u0130", "tr", u"\u0069", u"\u0130"},
    // Turkish/Azeri. Lowercasing can make the string shorter.
    {u"I\u0307", "tr", u"i", u"I\u0307", {{2, 1}}},
    // Lithuanian. Uppercasing can make the string shorter.
    {u"i\u0307", "lt", u"i\u0307", u"I", {}, {{2, 1}}},
    {u"i\u0307z", "lt", u"i\u0307z", u"IZ", {}, {{2, 1}}},
    {u"xi\u0307", "lt", u"xi\u0307", u"XI", {}, {{3, 2}}},
    {u"xi\u0307z", "lt", u"xi\u0307z", u"XIZ", {}, {{3, 2}}},
    // Lithuanian. Lowercasing can make the string longer.
    {u"\u00CC", "lt", u"\u0069\u0307\u0300", u"\u00CC", {{1, 3}}},
    // Mix of longer ones and shorter ones.
    {u"\u00DFi\u0307", "lt", u"\u00DFi\u0307", u"SSI", {}, {{1, 2}, {3, 3}}},
    {u"\u00DFyi\u0307z",
     "lt",
     u"\u00DFyi\u0307z",
     u"SSYIZ",
     {},
     {{1, 2}, {4, 4}}},
    {u"i\u0307\u00DF", "lt", u"i\u0307\u00DF", u"ISS", {}, {{2, 1}, {3, 3}}},
};

std::ostream& operator<<(std::ostream& os, const CaseMapTestData& data) {
  return os << String(data.source) << " locale=" << data.locale;
}

class CaseMapTest : public testing::Test,
                    public testing::WithParamInterface<CaseMapTestData> {};

INSTANTIATE_TEST_SUITE_P(CaseMapTest,
                         CaseMapTest,
                         testing::ValuesIn(case_map_test_data));

TEST_P(CaseMapTest, ToLowerWithoutOffset) {
  const auto data = GetParam();
  CaseMap case_map(AtomicString(data.locale));
  String source(data.source);
  String lower = case_map.ToLower(source);
  EXPECT_EQ(lower, String(data.lower_expected));
}

TEST_P(CaseMapTest, ToUpperWithoutOffset) {
  const auto data = GetParam();
  CaseMap case_map(AtomicString(data.locale));
  String source(data.source);
  String upper = case_map.ToUpper(source);
  EXPECT_EQ(upper, String(data.upper_expected));
}

TEST_P(CaseMapTest, ToLower) {
  const auto data = GetParam();
  CaseMap case_map(AtomicString(data.locale));
  String source(data.source);
  TextOffsetMap offset_map;
  String lower = case_map.ToLower(source, &offset_map);
  EXPECT_EQ(lower, String(data.lower_expected));
  EXPECT_THAT(offset_map.Entries(), ElementsAreArray(data.lower_map));
}

TEST_P(CaseMapTest, ToUpper) {
  const auto data = GetParam();
  CaseMap case_map(AtomicString(data.locale));
  String source(data.source);
  TextOffsetMap offset_map;
  String upper = case_map.ToUpper(source, &offset_map);
  EXPECT_EQ(upper, String(data.upper_expected));
  EXPECT_THAT(offset_map.Entries(), ElementsAreArray(data.upper_map));
}

TEST_P(CaseMapTest, ToLower8Bit) {
  const auto data = GetParam();
  String source(data.source);
  source = To8BitOrNull(source);
  if (!source)
    return;
  CaseMap case_map(AtomicString(data.locale));
  TextOffsetMap offset_map;
  String lower = case_map.ToLower(source, &offset_map);
  EXPECT_EQ(lower, String(data.lower_expected));
  EXPECT_THAT(offset_map.Entries(), ElementsAreArray(data.lower_map));
}

TEST_P(CaseMapTest, ToUpper8Bit) {
  const auto data = GetParam();
  String source(data.source);
  source = To8BitOrNull(source);
  if (!source)
    return;
  CaseMap case_map(AtomicString(data.locale));
  TextOffsetMap offset_map;
  String upper = case_map.ToUpper(source, &offset_map);
  EXPECT_EQ(upper, String(data.upper_expected));
  EXPECT_THAT(offset_map.Entries(), ElementsAreArray(data.upper_map));
}

struct CaseFoldingTestData {
  const char* source_description;
  const char* source;
  base::span<const char*> locale_list;
  const char* expected;
};

// \xC4\xB0 = U+0130 (capital dotted I)
// \xC4\xB1 = U+0131 (lowercase dotless I)
const char* g_turkic_input = "Isi\xC4\xB0 \xC4\xB0s\xC4\xB1I";
const char* g_greek_input =
    "\xCE\x9F\xCE\x94\xCE\x8C\xCE\xA3 \xCE\x9F\xCE\xB4\xCF\x8C\xCF\x82 "
    "\xCE\xA3\xCE\xBF \xCE\xA3\xCE\x9F o\xCE\xA3 \xCE\x9F\xCE\xA3 \xCF\x83 "
    "\xE1\xBC\x95\xCE\xBE";
const char* g_lithuanian_input =
    "I \xC3\x8F J J\xCC\x88 \xC4\xAE \xC4\xAE\xCC\x88 \xC3\x8C \xC3\x8D "
    "\xC4\xA8 xi\xCC\x87\xCC\x88 xj\xCC\x87\xCC\x88 x\xC4\xAF\xCC\x87\xCC\x88 "
    "xi\xCC\x87\xCC\x80 xi\xCC\x87\xCC\x81 xi\xCC\x87\xCC\x83 XI X\xC3\x8F XJ "
    "XJ\xCC\x88 X\xC4\xAE X\xC4\xAE\xCC\x88";

const char* g_turkic_locales[] = {
    "tr", "tr-TR", "tr_TR", "tr@foo=bar", "tr-US", "TR", "tr-tr", "tR",
    "az", "az-AZ", "az_AZ", "az@foo=bar", "az-US", "Az", "AZ-AZ",
};
const char* g_non_turkic_locales[] = {
    "en", "en-US", "en_US", "en@foo=bar", "EN", "En",
    "ja", "el",    "fil",   "fi",         "lt",
};
const char* g_greek_locales[] = {
    "el", "el-GR", "el_GR", "el@foo=bar", "el-US", "EL", "el-gr", "eL",
};
const char* g_non_greek_locales[] = {
    "en", "en-US", "en_US", "en@foo=bar", "EN", "En",
    "ja", "tr",    "az",    "fil",        "fi", "lt",
};
const char* g_lithuanian_locales[] = {
    "lt", "lt-LT", "lt_LT", "lt@foo=bar", "lt-US", "LT", "lt-lt", "lT",
};
// Should not have "tr" or "az" because "lt" and 'tr/az' rules conflict with
// each other.
const char* g_non_lithuanian_locales[] = {
    "en", "en-US", "en_US", "en@foo=bar", "EN", "En", "ja", "fil", "fi", "el",
};

TEST(CaseMapTest, ToUpperLocale) {
  const auto test_data_list = std::to_array<CaseFoldingTestData>({
      {
          "Turkic input",
          g_turkic_input,
          g_turkic_locales,
          "IS\xC4\xB0\xC4\xB0 \xC4\xB0SII",
      },
      {
          "Turkic input",
          g_turkic_input,
          g_non_turkic_locales,
          "ISI\xC4\xB0 \xC4\xB0SII",
      },
      {
          "Greek input",
          g_greek_input,
          g_greek_locales,
          "\xCE\x9F\xCE\x94\xCE\x9F\xCE\xA3 \xCE\x9F\xCE\x94\xCE\x9F\xCE\xA3 "
          "\xCE\xA3\xCE\x9F \xCE\xA3\xCE\x9F \x4F\xCE\xA3 \xCE\x9F\xCE\xA3 "
          "\xCE\xA3 \xCE\x95\xCE\x9E",
      },
      {
          "Greek input",
          g_greek_input,
          g_non_greek_locales,
          "\xCE\x9F\xCE\x94\xCE\x8C\xCE\xA3 \xCE\x9F\xCE\x94\xCE\x8C\xCE\xA3 "
          "\xCE\xA3\xCE\x9F \xCE\xA3\xCE\x9F \x4F\xCE\xA3 \xCE\x9F\xCE\xA3 "
          "\xCE\xA3 \xE1\xBC\x9D\xCE\x9E",
      },
      {
          "Lithuanian input",
          g_lithuanian_input,
          g_lithuanian_locales,
          "I \xC3\x8F J J\xCC\x88 \xC4\xAE \xC4\xAE\xCC\x88 \xC3\x8C \xC3\x8D "
          "\xC4\xA8 XI\xCC\x88 XJ\xCC\x88 X\xC4\xAE\xCC\x88 XI\xCC\x80 "
          "XI\xCC\x81 XI\xCC\x83 XI X\xC3\x8F XJ XJ\xCC\x88 X\xC4\xAE "
          "X\xC4\xAE\xCC\x88",
      },
      {
          "Lithuanian input",
          g_lithuanian_input,
          g_non_lithuanian_locales,
          "I \xC3\x8F J J\xCC\x88 \xC4\xAE \xC4\xAE\xCC\x88 \xC3\x8C \xC3\x8D "
          "\xC4\xA8 XI\xCC\x87\xCC\x88 XJ\xCC\x87\xCC\x88 "
          "X\xC4\xAE\xCC\x87\xCC\x88 XI\xCC\x87\xCC\x80 XI\xCC\x87\xCC\x81 "
          "XI\xCC\x87\xCC\x83 XI X\xC3\x8F XJ XJ\xCC\x88 X\xC4\xAE "
          "X\xC4\xAE\xCC\x88",
      },
  });

  for (const auto& test_data : test_data_list) {
    const char* expected = test_data.expected;
    String source = String::FromUTF8(test_data.source);
    for (const auto& locale : test_data.locale_list) {
      CaseMap case_map{AtomicString(locale)};
      EXPECT_EQ(expected, case_map.ToUpper(source).Utf8())
          << test_data.source_description << "; locale=" << locale;
    }
  }
}

TEST(CaseMapTest, ToLowerLocale) {
  const auto test_data_list = std::to_array<CaseFoldingTestData>({
      {
          "Turkic input",
          g_turkic_input,
          g_turkic_locales,
          "\xC4\xB1sii is\xC4\xB1\xC4\xB1",
      },
      {
          "Turkic input",
          g_turkic_input,
          g_non_turkic_locales,
          // U+0130 is lowercased to U+0069 followed by U+0307
          "isii\xCC\x87 i\xCC\x87s\xC4\xB1i",
      },
      {
          "Greek input",
          g_greek_input,
          g_greek_locales,
          "\xCE\xBF\xCE\xB4\xCF\x8C\xCF\x82 \xCE\xBF\xCE\xB4\xCF\x8C\xCF\x82 "
          "\xCF\x83\xCE\xBF \xCF\x83\xCE\xBF \x6F\xCF\x82 \xCE\xBF\xCF\x82 "
          "\xCF\x83 \xE1\xBC\x95\xCE\xBE",
      },
      {
          "Greek input",
          g_greek_input,
          g_non_greek_locales,
          "\xCE\xBF\xCE\xB4\xCF\x8C\xCF\x82 \xCE\xBF\xCE\xB4\xCF\x8C\xCF\x82 "
          "\xCF\x83\xCE\xBF \xCF\x83\xCE\xBF \x6F\xCF\x82 \xCE\xBF\xCF\x82 "
          "\xCF\x83 \xE1\xBC\x95\xCE\xBE",
      },
      {
          "Lithuanian input",
          g_lithuanian_input,
          g_lithuanian_locales,
          "i \xC3\xAF j j\xCC\x87\xCC\x88 \xC4\xAF \xC4\xAF\xCC\x87\xCC\x88 "
          "i\xCC\x87\xCC\x80 i\xCC\x87\xCC\x81 i\xCC\x87\xCC\x83 "
          "xi\xCC\x87\xCC\x88 xj\xCC\x87\xCC\x88 x\xC4\xAF\xCC\x87\xCC\x88 "
          "xi\xCC\x87\xCC\x80 xi\xCC\x87\xCC\x81 xi\xCC\x87\xCC\x83 xi "
          "x\xC3\xAF xj xj\xCC\x87\xCC\x88 x\xC4\xAF x\xC4\xAF\xCC\x87\xCC\x88",
      },
      {
          "Lithuanian input",
          g_lithuanian_input,
          g_non_lithuanian_locales,
          "\x69 \xC3\xAF \x6A \x6A\xCC\x88 \xC4\xAF \xC4\xAF\xCC\x88 \xC3\xAC "
          "\xC3\xAD \xC4\xA9 \x78\x69\xCC\x87\xCC\x88 \x78\x6A\xCC\x87\xCC\x88 "
          "\x78\xC4\xAF\xCC\x87\xCC\x88 \x78\x69\xCC\x87\xCC\x80 "
          "\x78\x69\xCC\x87\xCC\x81 \x78\x69\xCC\x87\xCC\x83 \x78\x69 "
          "\x78\xC3\xAF \x78\x6A \x78\x6A\xCC\x88 \x78\xC4\xAF "
          "\x78\xC4\xAF\xCC\x88",
      },
  });

  for (const auto& test_data : test_data_list) {
    const char* expected = test_data.expected;
    String source = String::FromUTF8(test_data.source);
    for (const auto& locale : test_data.locale_list) {
      CaseMap case_map{AtomicString(locale)};
      EXPECT_EQ(expected, case_map.ToLower(source).Utf8())
          << test_data.source_description << "; locale=" << locale;
    }
  }
}

}  // namespace WTF

"""

```
Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `hyphenation_test.cc` immediately suggests this file tests hyphenation functionality. The inclusion of `<hyphenation.h>` confirms this. We're looking at unit tests for a hyphenation library.

2. **Scan for Key Classes and Functions:**  A quick scan reveals the main class being tested is `Hyphenation`. We see concrete implementations like `NoHyphenation` and (conditionally) `HyphenationMinikin`. The test fixture `HyphenationTest` contains helper methods. Key functions within `Hyphenation` (or its implementations) are `LastHyphenLocation`, `FirstHyphenLocation`, and `HyphenLocations`.

3. **Understand the Testing Framework:** The presence of `#include "testing/gmock/include/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test and Google Mock frameworks for writing the tests. This tells us tests are defined using `TEST_F` and assertions are done using `EXPECT_EQ`, `EXPECT_THAT`, `ASSERT_TRUE`, etc.

4. **Analyze Individual Test Cases:**  Go through each `TEST_F` block and understand what it's testing.

    * **`Get`:** Tests the retrieval of `Hyphenation` objects based on locale. It seems to involve a `LayoutLocale` class that manages these instances.
    * **`MapLocale` (conditional):** Tests a mapping function that transforms locale strings into specific dictionary names or canonical forms. The conditions (`USE_MINIKIN_HYPHENATION`) are important—this functionality might only be present on certain platforms or builds.
    * **`HyphenLocations` (conditional):** Tests the core hyphenation logic. It checks if the `HyphenLocations` function returns the correct hyphenation points within a word, and verifies the order of the results. It also tests `FirstHyphenLocation` and `LastHyphenLocation`.
    * **`WordToHyphenate` (conditional):** Focuses on a utility function that appears to preprocess words before hyphenation, possibly stripping leading/trailing non-alphanumeric characters.
    * **`LeadingSpaces` (conditional):** Examines how leading spaces are handled during hyphenation.
    * **`NonLetters` (conditional):** Checks how sequences of non-letter characters are treated (likely no hyphenation).
    * **`English` (conditional):** Tests hyphenation for English, comparing the results against expected hyphenation points.
    * **`German` (conditional):** Tests hyphenation for German, considering non-ASCII characters.
    * **`CapitalizedWords` (conditional):**  Investigates how capitalization affects hyphenation in different languages (English vs. German).
    * **`SetLimits` (conditional):**  Tests the functionality of setting limits on the minimum prefix, suffix, and word length for hyphenation. This relates to the `hyphenate-limit-chars` CSS property.
    * **`Limits` (conditional):**  Tests the actual application of the limits set in the previous test, verifying that hyphenation points are correctly suppressed when the limits are violated.

5. **Identify Connections to Web Technologies:** Based on the tested functionalities, draw connections to JavaScript, HTML, and CSS:

    * **CSS:**  The `hyphenate-limit-chars` property is directly related to the `SetLimits` and `Limits` tests. The overall purpose of hyphenation is driven by CSS properties like `hyphens`.
    * **HTML:** Hyphenation is applied to the text content within HTML elements. The tests implicitly assume the input is text extracted from HTML.
    * **JavaScript:** While this specific file doesn't directly interact with JavaScript, the hyphenation logic it tests is used by the browser's rendering engine, which can be controlled or interacted with by JavaScript. For instance, JavaScript could dynamically change the text content or the language/locale, impacting hyphenation.

6. **Analyze Logic and Assumptions:**  Consider the assumptions made in the tests and how the logic works:

    * **Locale-Specific Behavior:** The tests heavily rely on locale-specific hyphenation rules. This is a core assumption.
    * **Minikin (Conditional):** The frequent checks for `USE_MINIKIN_HYPHENATION` and `BUILDFLAG(IS_APPLE)` indicate platform-specific implementations of hyphenation.
    * **Helper Functions:** The `FirstHyphenLocations` and `LastHyphenLocations` helper functions provide a way to test iterating through hyphenation points.
    * **Edge Cases:** The tests cover edge cases like leading spaces, non-letter characters, and capitalized words.

7. **Consider User and Programming Errors:** Think about how incorrect usage or assumptions might lead to problems:

    * **Incorrect Locale:**  Specifying the wrong locale will lead to incorrect hyphenation.
    * **Missing Dictionaries:** If hyphenation dictionaries are not available for a given locale, hyphenation will not work (or a default behavior will be used).
    * **Misunderstanding Limits:** Developers might misunderstand how `hyphenate-limit-chars` works, leading to unexpected hyphenation behavior.

8. **Structure the Explanation:** Organize the findings into logical sections, as shown in the provided good answer. Start with the main purpose, then elaborate on specific functionalities, connections to web technologies, logic, and potential errors. Use clear and concise language. Provide concrete examples to illustrate the points.

9. **Review and Refine:**  Read through the explanation to ensure accuracy and clarity. Check for any missing information or areas that could be explained better. For instance, initially, I might not have explicitly mentioned the role of `LayoutLocale`, but upon closer inspection, its importance becomes clear, and it should be included in the explanation.
这个C++文件 `hyphenation_test.cc` 是 Chromium Blink 渲染引擎中用于测试 **文本断字 (hyphenation)** 功能的单元测试文件。它的主要目的是验证 `blink::Hyphenation` 类及其相关实现是否按照预期工作。

以下是该文件的功能分解：

**1. 定义和测试 `Hyphenation` 接口:**

*   该文件定义了一个抽象基类 `Hyphenation`，它声明了断字操作所需的核心方法，例如：
    *   `LastHyphenLocation(const StringView&, wtf_size_t before_index) const override;`:  查找给定字符串中指定索引之前最后一个可能的断字位置。
    *   `FirstHyphenLocation` (在 `HyphenationTest` 中使用，但未在基类中直接声明): 查找给定字符串中指定索引之后第一个可能的断字位置。
    *   `HyphenLocations` (在 `HyphenationTest` 中使用，但未在基类中直接声明): 返回给定字符串中所有可能的断字位置。

*   它还定义了一个简单的 `NoHyphenation` 类，该类继承自 `Hyphenation`，但其 `LastHyphenLocation` 始终返回 0，表示不进行断字。这用于测试在禁用断字时的行为。

**2. 测试 `Hyphenation` 接口的具体实现:**

*   该文件主要测试了 `HyphenationMinikin` 类（当定义了 `USE_MINIKIN_HYPHENATION` 时）的实现，这通常是基于 Minikin 库的断字实现。
*   它还包含在 Apple 平台上的断字测试（当定义了 `BUILDFLAG(IS_APPLE)` 时），这可能使用了不同的断字实现。

**3. 测试断字的核心逻辑:**

*   **查找断字点:** 测试 `HyphenLocations` 方法是否能正确识别单词中的断字点。
*   **查找第一个/最后一个断字点:** 测试 `FirstHyphenLocation` 和 `LastHyphenLocation` 方法在给定索引附近查找断字点的功能。
*   **处理不同语言:**  测试针对不同语言（例如英语 "en-us" 和德语 "de-1996"）的断字规则是否正确应用。这通过加载特定语言的断字字典来实现。
*   **处理大小写:**  测试断字功能如何处理首字母大写的单词，例如在英语中通常避免对首字母大写的单词进行断字。
*   **处理前导空格和非字母字符:**  测试断字功能如何处理单词前的空格以及单词中的非字母字符。
*   **设置断字限制:** 测试与 CSS `hyphenate-limit-chars` 属性相关的设置，例如限制断字前后的最小字符数以及单词的最小长度。

**与 JavaScript, HTML, CSS 的关系:**

该文件测试的 `Hyphenation` 类是 Blink 渲染引擎中用于实现 CSS 断字相关属性的基础。

*   **CSS `hyphens` 属性:**  这个 CSS 属性控制文本是否进行断字。`Hyphenation` 类的功能直接支持 `hyphens: auto;` 的行为，即浏览器自动根据语言规则进行断字。
*   **CSS `hyphenate-limit-chars` 属性:** 这个 CSS 属性允许开发者指定断字的最小前缀长度、最小后缀长度以及单词的最小长度。`hyphenation_test.cc` 中的 `TEST_F(HyphenationTest, SetLimits)` 和 `TEST_F(HyphenationTest, Limits)` 测试了 `Hyphenation` 类如何处理这些限制。
*   **HTML `lang` 属性:**  HTML 元素的 `lang` 属性指定了元素的语言，这直接影响了 `Hyphenation` 类选择哪个语言的断字规则和字典。测试用例中使用了例如 `"en-us"` 和 `"de-1996"` 这样的语言代码。
*   **JavaScript:** JavaScript 本身不直接操作底层的断字逻辑，但 JavaScript 可以通过修改 HTML 元素的文本内容或 `lang` 属性来间接影响断字的结果。例如，JavaScript 可以动态地改变元素的语言，从而触发不同的断字规则。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*   **语言:** "en-us"
*   **单词:** "example"
*   **断字对象:**  一个为 "en-us" 语言配置的 `HyphenationMinikin` 实例。
*   **方法调用:** `hyphenation->HyphenLocations("example")`

**预期输出:**

*   一个包含数字 `4` 和 `2` 的向量 (`Vector<wtf_size_t, 8>`)，表示单词 "ex**am**ple" 和 "examp**le**" 的断字点。

**假设输入:**

*   **语言:** "de-de"
*   **单词:** "Konsonantien"
*   **断字对象:** 一个为 "de-1996" 语言配置的 `HyphenationMinikin` 实例。
*   **方法调用:** `hyphenation->HyphenLocations("Konsonantien")`

**预期输出:**

*   一个包含数字 `10`, `8`, `5`, `3` (或类似断字点的向量，取决于具体的德语断字规则) 的向量，表示单词 "Konso**nan**ti**en**" 的断字点。

**用户或编程常见的使用错误:**

1. **未设置或错误设置 `lang` 属性:**  如果 HTML 元素的 `lang` 属性没有设置或者设置了错误的语言代码，浏览器将无法使用正确的断字规则。例如，一个德语文本块的 `lang` 属性设置为 `"en"`，会导致使用英语的断字规则，从而产生错误的断字结果。

    ```html
    <!-- 错误的语言设置 -->
    <p lang="en">Dies ist ein deutsches Wort.</p>
    ```

2. **依赖于所有语言的断字字典都存在:**  浏览器可能只内置了部分常用语言的断字字典。如果尝试对一个没有对应字典的语言进行断字，结果可能不正确或者根本不进行断字。

3. **误解 `hyphenate-limit-chars` 的作用:**  开发者可能不清楚 `hyphenate-limit-chars` 属性的具体作用，导致设置了不合理的限制，从而阻止了本应进行的断字。例如，设置 `hyphenate-limit-chars: 6 3;` 意味着断字前至少要有 6 个字符，断字后至少要有 3 个字符，这可能会阻止对短单词的断字。

    ```css
    p {
      hyphens: auto;
      -webkit-hyphenate-limit-chars: 6 3; /* 可能会阻止对 "example" 进行断字 */
    }
    ```

4. **在不支持断字的浏览器中使用:**  虽然现代浏览器基本都支持 CSS 断字，但在一些旧版本的浏览器中可能不支持。开发者需要考虑兼容性问题。

5. **期望在所有情况下都完美断字:**  断字算法和字典可能并不完美，对于一些复杂的词汇或特殊情况，可能无法得到理想的断字结果。

总而言之，`hyphenation_test.cc` 是 Blink 引擎中至关重要的测试文件，它确保了文本断字功能的正确性和可靠性，而这一功能直接影响着网页文本的排版和可读性。

Prompt: 
```
这是目录为blink/renderer/platform/text/hyphenation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/text/hyphenation.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/text/layout_locale.h"

using testing::ElementsAre;
using testing::ElementsAreArray;

#if defined(USE_MINIKIN_HYPHENATION) && BUILDFLAG(IS_FUCHSIA)
// Fuchsia doesn't include |blink_platform_unittests_data|.
#undef USE_MINIKIN_HYPHENATION
#endif

#if defined(USE_MINIKIN_HYPHENATION)
#include "base/files/file_path.h"
#include "third_party/blink/renderer/platform/text/hyphenation/hyphenation_minikin.h"
#endif

namespace blink {

class NoHyphenation : public Hyphenation {
 public:
  wtf_size_t LastHyphenLocation(const StringView&,
                                wtf_size_t before_index) const override {
    return 0;
  }
};

class HyphenationTest : public testing::Test {
 protected:
  void TearDown() override { LayoutLocale::ClearForTesting(); }

#if defined(USE_MINIKIN_HYPHENATION) || BUILDFLAG(IS_APPLE)
  // Get a |Hyphenation| instance for the specified locale for testing.
  scoped_refptr<Hyphenation> GetHyphenation(const AtomicString& locale) {
#if defined(USE_MINIKIN_HYPHENATION)
    // Because the mojo service to open hyphenation dictionaries is not
    // accessible from the unit test, open the dictionary file directly for
    // testing.
    std::string filename = "hyph-" + locale.Ascii() + ".hyb";
#if BUILDFLAG(IS_ANDROID)
    base::FilePath path("/system/usr/hyphen-data");
#else
    base::FilePath path = test::HyphenationDictionaryDir();
#endif
    path = path.AppendASCII(filename);
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
    if (file.IsValid())
      return HyphenationMinikin::FromFileForTesting(locale, std::move(file));
#else
    if (const LayoutLocale* layout_locale = LayoutLocale::Get(locale))
      return layout_locale->GetHyphenation();
#endif
    return nullptr;
  }

  Vector<wtf_size_t> FirstHyphenLocations(
      StringView word,
      const Hyphenation& hyphenation) const {
    Vector<wtf_size_t> indexes;
    const wtf_size_t word_len = word.length();
    for (wtf_size_t i = 0; i < word_len; ++i)
      indexes.push_back(hyphenation.FirstHyphenLocation(word, i));
    return indexes;
  }

  Vector<wtf_size_t> LastHyphenLocations(StringView word,
                                         const Hyphenation& hyphenation) const {
    Vector<wtf_size_t> indexes;
    const wtf_size_t word_len = word.length();
    for (wtf_size_t i = 0; i < word_len; ++i)
      indexes.push_back(hyphenation.LastHyphenLocation(word, i));
    return indexes;
  }
#endif

#if defined(USE_MINIKIN_HYPHENATION)
  void TestWordToHyphenate(StringView text,
                           StringView expected,
                           unsigned expected_num_leading_chars) {
    unsigned num_leading_chars;
    const StringView result =
        HyphenationMinikin::WordToHyphenate(text, &num_leading_chars);
    EXPECT_EQ(result, expected);
    EXPECT_EQ(num_leading_chars, expected_num_leading_chars);

    // |WordToHyphenate| has separate codepaths for 8 and 16 bits. Make sure
    // both codepaths return the same results. When a paragraph has at least one
    // 16 bits character (e.g., Emoji), there will be 8 bits words in 16 bits
    // string.
    if (!text.Is8Bit()) {
      // If |text| is 16 bits, 16 bits codepath is already tested.
      return;
    }
    String text16 = text.ToString();
    text16.Ensure16Bit();
    const StringView result16 =
        HyphenationMinikin::WordToHyphenate(text16, &num_leading_chars);
    EXPECT_EQ(result16, expected);
    EXPECT_EQ(num_leading_chars, expected_num_leading_chars);
  }
#endif
};

TEST_F(HyphenationTest, Get) {
  scoped_refptr<Hyphenation> hyphenation = base::AdoptRef(new NoHyphenation);
  AtomicString local_en_us("en-US");
  LayoutLocale::SetHyphenationForTesting(local_en_us, hyphenation);
  EXPECT_EQ(hyphenation.get(),
            LayoutLocale::Get(local_en_us)->GetHyphenation());
  AtomicString local_en_uk("en-UK");
  LayoutLocale::SetHyphenationForTesting(local_en_uk, nullptr);
  EXPECT_EQ(nullptr, LayoutLocale::Get(local_en_uk)->GetHyphenation());
}

#if defined(USE_MINIKIN_HYPHENATION)
TEST_F(HyphenationTest, MapLocale) {
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("de-de")), "de-1996");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("de-de-xyz")),
            "de-1996");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("de-li")), "de-1996");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("de-li-1901")),
            "de-ch-1901");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("en")), "en-us");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("en-gu")), "en-us");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("en-gu-xyz")), "en-us");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("en-xyz")), "en-gb");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("en-xyz-xyz")), "en-gb");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("fr-ca")), "fr");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("fr-fr")), "fr");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("fr-fr-xyz")), "fr");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("mn-xyz")), "mn-cyrl");
  EXPECT_EQ(HyphenationMinikin::MapLocale(AtomicString("und-Deva-xyz")), "hi");

  const char* no_map_locales[] = {"en-us", "fr"};
  for (const char* locale_str : no_map_locales) {
    AtomicString locale(locale_str);
    AtomicString mapped_locale = HyphenationMinikin::MapLocale(locale);
    // If no mapping, the same instance should be returned.
    EXPECT_EQ(locale.Impl(), mapped_locale.Impl());
  }
}
#endif

#if defined(USE_MINIKIN_HYPHENATION) || BUILDFLAG(IS_APPLE)
TEST_F(HyphenationTest, HyphenLocations) {
  scoped_refptr<Hyphenation> hyphenation =
      GetHyphenation(AtomicString("en-us"));
#if BUILDFLAG(IS_ANDROID)
  // Hyphenation is available only for Android M MR1 or later.
  if (!hyphenation)
    return;
#endif
  ASSERT_TRUE(hyphenation) << "Cannot find the hyphenation for en-us";

  // Get all hyphenation points by |HyphenLocations|.
  const String word("hyphenation");
  Vector<wtf_size_t, 8> locations = hyphenation->HyphenLocations(word);
  EXPECT_GT(locations.size(), 0u);

  for (wtf_size_t i = 1; i < locations.size(); i++) {
    ASSERT_GT(locations[i - 1], locations[i])
        << "hyphenLocations must return locations in the descending order";
  }

  // Test |LastHyphenLocation| returns all hyphenation points.
  Vector<wtf_size_t, 8> actual;
  for (wtf_size_t offset = word.length();;) {
    offset = hyphenation->LastHyphenLocation(word, offset);
    if (!offset)
      break;
    actual.push_back(offset);
  }
  EXPECT_THAT(actual, ElementsAreArray(locations));

  // Test |FirstHyphenLocation| returns all hyphenation points.
  actual.clear();
  for (wtf_size_t offset = 0;;) {
    offset = hyphenation->FirstHyphenLocation(word, offset);
    if (!offset)
      break;
    actual.push_back(offset);
  }
  locations.Reverse();
  EXPECT_THAT(actual, ElementsAreArray(locations));
}

#if defined(USE_MINIKIN_HYPHENATION)
TEST_F(HyphenationTest, WordToHyphenate) {
  TestWordToHyphenate("word", "word", 0);
  TestWordToHyphenate(" word", "word", 1);
  TestWordToHyphenate("  word", "word", 2);
  TestWordToHyphenate("  word..", "word", 2);
  TestWordToHyphenate(" ( word. ).", "word", 3);
  TestWordToHyphenate(u" ( \u3042. ).", u"\u3042", 3);
  TestWordToHyphenate(u" ( \U00020B9F. ).", u"\U00020B9F", 3);
}
#endif

TEST_F(HyphenationTest, LeadingSpaces) {
  scoped_refptr<Hyphenation> hyphenation =
      GetHyphenation(AtomicString("en-us"));
#if BUILDFLAG(IS_ANDROID)
  // Hyphenation is available only for Android M MR1 or later.
  if (!hyphenation)
    return;
#endif
  ASSERT_TRUE(hyphenation) << "Cannot find the hyphenation for en-us";

  String leading_space(" principle");
  EXPECT_THAT(hyphenation->HyphenLocations(leading_space), ElementsAre(7, 5));
  EXPECT_EQ(5u, hyphenation->LastHyphenLocation(leading_space, 6));

  String multi_leading_spaces("   principle");
  EXPECT_THAT(hyphenation->HyphenLocations(multi_leading_spaces),
              ElementsAre(9, 7));
  EXPECT_EQ(7u, hyphenation->LastHyphenLocation(multi_leading_spaces, 8));

  // Line breaker is not supposed to pass only spaces, no locations.
  String only_spaces("   ");
  EXPECT_THAT(hyphenation->HyphenLocations(only_spaces), ElementsAre());
  EXPECT_EQ(0u, hyphenation->LastHyphenLocation(only_spaces, 3));
}

TEST_F(HyphenationTest, NonLetters) {
  scoped_refptr<Hyphenation> hyphenation =
      GetHyphenation(AtomicString("en-us"));
#if BUILDFLAG(IS_ANDROID)
  // Hyphenation is available only for Android M MR1 or later.
  if (!hyphenation)
    return;
#endif

  String non_letters("**********");
  EXPECT_EQ(0u,
            hyphenation->LastHyphenLocation(non_letters, non_letters.length()));

  non_letters.Ensure16Bit();
  EXPECT_EQ(0u,
            hyphenation->LastHyphenLocation(non_letters, non_letters.length()));
}

TEST_F(HyphenationTest, English) {
  scoped_refptr<Hyphenation> hyphenation =
      GetHyphenation(AtomicString("en-us"));
#if BUILDFLAG(IS_ANDROID)
  // Hyphenation is available only for Android M MR1 or later.
  if (!hyphenation)
    return;
#endif
  ASSERT_TRUE(hyphenation) << "Cannot find the hyphenation for en-us";

  Vector<wtf_size_t, 8> locations = hyphenation->HyphenLocations("hyphenation");
  EXPECT_THAT(locations, testing::AnyOf(ElementsAreArray({6, 2}),
                                        ElementsAreArray({7, 6, 2})));
}

TEST_F(HyphenationTest, German) {
  scoped_refptr<Hyphenation> hyphenation =
      GetHyphenation(AtomicString("de-1996"));
#if BUILDFLAG(IS_ANDROID)
  // Hyphenation is available only for Android M MR1 or later.
  if (!hyphenation)
    return;
#endif
  ASSERT_TRUE(hyphenation) << "Cannot find the hyphenation for de-1996";

  Vector<wtf_size_t, 8> locations =
      hyphenation->HyphenLocations("konsonantien");
#if BUILDFLAG(IS_APPLE)
  EXPECT_THAT(locations, ElementsAreArray({10, 8, 5, 3}));
#else
  EXPECT_THAT(locations, ElementsAreArray({8, 5, 3}));
#endif

  // Test words with non-ASCII (> U+0080) characters.
  locations = hyphenation->HyphenLocations(
      "B"
      "\xE4"  // LATIN SMALL LETTER A WITH DIAERESIS
      "chlein");
  EXPECT_THAT(locations, ElementsAreArray({4}));
}
#endif

#if defined(USE_MINIKIN_HYPHENATION) || BUILDFLAG(IS_APPLE)
TEST_F(HyphenationTest, CapitalizedWords) {
  // Avoid hyphenating capitalized words for "en".
  if (scoped_refptr<Hyphenation> en = GetHyphenation(AtomicString("en-us"))) {
    Vector<wtf_size_t, 8> locations = en->HyphenLocations("Hyphenation");
    EXPECT_EQ(locations.size(), 0u);
  }

  // Hyphenate capitalized words if German.
  if (scoped_refptr<Hyphenation> de = GetHyphenation(AtomicString("de-1996"))) {
    Vector<wtf_size_t, 8> locations = de->HyphenLocations("Konsonantien");
    EXPECT_NE(locations.size(), 0u);
  }
}

// Test the used values of the `hyphenate-limit-chars` property.
// https://w3c.github.io/csswg-drafts/css-text-4/#propdef-hyphenate-limit-chars
TEST_F(HyphenationTest, SetLimits) {
  scoped_refptr<Hyphenation> en = GetHyphenation(AtomicString("en-us"));
  if (!en)
    return;

  en->SetLimits(0, 0, 0);
  EXPECT_THAT(en->MinPrefixLength(), Hyphenation::kDefaultMinPrefixLength);
  EXPECT_THAT(en->MinSuffixLength(), Hyphenation::kDefaultMinSuffixLength);
  EXPECT_THAT(en->MinWordLength(), Hyphenation::kDefaultMinWordLength);

  const wtf_size_t word = Hyphenation::kDefaultMinWordLength + 1;
  en->SetLimits(0, 0, word);
  EXPECT_THAT(en->MinPrefixLength(), Hyphenation::kDefaultMinPrefixLength);
  EXPECT_THAT(en->MinSuffixLength(), Hyphenation::kDefaultMinSuffixLength);
  EXPECT_THAT(en->MinWordLength(), word);

  const wtf_size_t prefix = Hyphenation::kDefaultMinPrefixLength + 1;
  const wtf_size_t suffix = Hyphenation::kDefaultMinSuffixLength + 10;
  en->SetLimits(prefix, suffix, 0);
  EXPECT_THAT(en->MinPrefixLength(), prefix);
  EXPECT_THAT(en->MinSuffixLength(), suffix);
  EXPECT_THAT(en->MinWordLength(),
              std::max(prefix + suffix, Hyphenation::kDefaultMinWordLength));

  // If the `suffix` is missing, it is the same as the `prefix`.
  en->SetLimits(prefix, 0, 0);
  EXPECT_THAT(en->MinPrefixLength(), prefix);
  EXPECT_THAT(en->MinSuffixLength(), prefix);
  EXPECT_THAT(en->MinWordLength(),
              std::max(prefix + prefix, Hyphenation::kDefaultMinWordLength));

  // If the `prefix` is missing, it is `auto`.
  en->SetLimits(0, suffix, 0);
  EXPECT_THAT(en->MinPrefixLength(), Hyphenation::kDefaultMinPrefixLength);
  EXPECT_THAT(en->MinSuffixLength(), suffix);
  EXPECT_THAT(en->MinWordLength(),
              std::max(Hyphenation::kDefaultMinPrefixLength + suffix,
                       Hyphenation::kDefaultMinWordLength));

  en->ResetLimits();
}

// Test the limitation with all the 3 public APIs.
TEST_F(HyphenationTest, Limits) {
  scoped_refptr<Hyphenation> en = GetHyphenation(AtomicString("en-us"));
  if (!en)
    return;

  // "example" hyphenates to "ex-am-ple".
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre(4, 2));
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(2, 2, 4, 4, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 2, 2, 4, 4));

  // Limiting prefix >= 2 and suffix >= 3 doesn't affect results.
  en->SetLimits(2, 3, 0);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre(4, 2));
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(2, 2, 4, 4, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 2, 2, 4, 4));

  // Limiting the prefix >= 3 disables the first hyphenation point.
  en->SetLimits(3, 0, 0);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre(4));
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(4, 4, 4, 4, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 0, 0, 4, 4));

  // Limiting the suffix >= 4 disables the last hyphenation point.
  en->SetLimits(0, 4, 0);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre(2));
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(2, 2, 0, 0, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 2, 2, 2, 2));

  // Applying both limitations results in no hyphenation points.
  en->SetLimits(3, 4, 0);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre());
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 0, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 0, 0, 0, 0));

  // Limiting the word length >= 7 doesn't affect the results.
  en->SetLimits(0, 0, 7);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre(4, 2));
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(2, 2, 4, 4, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 2, 2, 4, 4));

  // Limiting the word length >= 8 disables hyphenating "example".
  en->SetLimits(0, 0, 8);
  EXPECT_THAT(en->HyphenLocations("example"), ElementsAre());
  EXPECT_THAT(FirstHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 0, 0, 0, 0));
  EXPECT_THAT(LastHyphenLocations("example", *en),
              ElementsAre(0, 0, 0, 0, 0, 0, 0));

  en->ResetLimits();
}
#endif  // defined(USE_MINIKIN_HYPHENATION) || BUILDFLAG(IS_APPLE)

}  // namespace blink

"""

```
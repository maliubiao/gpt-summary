Response:
My thought process for analyzing the `symbols_iterator_test.cc` file and generating the response would be as follows:

1. **Understand the Goal:** The request asks for the functionality of the given C++ test file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and potential usage errors.

2. **Identify the Core Functionality:** The file name `symbols_iterator_test.cc` immediately suggests it's a test file for something called `SymbolsIterator`. Reading the include statements confirms this, as it includes `symbols_iterator.h`.

3. **Analyze the Test Structure:**  I'd notice the use of the `testing/gtest/include/gtest/gtest.h` header, indicating the use of the Google Test framework. This immediately tells me it's a unit test file.

4. **Examine the Test Cases:** I would systematically go through each `TEST_P` and `TEST_F` block. For each test case, I'd try to understand:
    * **What is being tested?** What input is being provided to `SymbolsIterator`?
    * **What is the expected output?** What `FontFallbackPriority` is expected for different parts of the input string?
    * **What is the assertion doing?**  The `ASSERT_EQ` and `ASSERT_LT` calls verify the actual output matches the expected output.

5. **Identify Key Data Structures and Helper Functions:**
    * `FallbackTestRun`: Represents input text and its expected fallback priority.
    * `FallbackExpectedRun`: Represents the expected limit (end index) and fallback priority after processing a run.
    * `CheckRuns()`: A helper function to set up the input string and expected output runs, then call `VerifyRuns`.
    * `VerifyRuns()`: The core verification logic, iterating through the `SymbolsIterator` and comparing the consumed runs with the expected runs.

6. **Determine the Purpose of `SymbolsIterator`:** By observing the test cases and the `FontFallbackPriority` enum, I can deduce that `SymbolsIterator` is responsible for iterating through a string and identifying segments (runs) that should be rendered with different font fallback priorities. Specifically, it seems to distinguish between normal text and various types of emoji.

7. **Connect to Web Technologies:**  This is where I link the C++ code to the user-facing web technologies:
    * **JavaScript:**  JavaScript often handles text manipulation. The `SymbolsIterator`'s functionality is related to how JavaScript might internally handle or expose information about character types for rendering. I would think about JavaScript's string methods and how they might interact with this kind of segmentation.
    * **HTML:**  HTML provides the structure for text content. The results of the `SymbolsIterator` would inform how the browser renders that text, potentially using different fonts for different segments.
    * **CSS:**  CSS controls the styling of HTML elements, including font selection. The `FontFallbackPriority` determined by `SymbolsIterator` would directly influence the font fallback mechanism applied by the browser based on CSS rules (e.g., `font-family`).

8. **Construct Logical Reasoning Examples:**  I'd pick a few test cases and explicitly state the input and expected output, explaining *why* that output is expected based on the logic I've inferred for `SymbolsIterator`. For instance, the handling of variation selectors (VS15, VS16) and ZWJ sequences are good examples.

9. **Identify Potential User/Programming Errors:**  I'd think about common mistakes developers might make when dealing with text and fonts, and how `SymbolsIterator`'s logic relates to these. Examples include:
    * Incorrectly assuming all characters are rendered with the same font.
    * Not understanding how variation selectors affect emoji rendering.
    * Misinterpreting how ZWJ sequences create single emoji glyphs.

10. **Refine and Structure the Output:** Finally, I'd organize my findings into the requested categories (Functionality, Relationship to Web Technologies, Logical Reasoning, Usage Errors), providing clear explanations and examples for each. I'd also ensure the language is accessible and avoids overly technical jargon where possible. I'd review to make sure I addressed all parts of the prompt.
这个文件 `symbols_iterator_test.cc` 是 Chromium Blink 引擎中的一个 C++ 测试文件，它专门用于测试 `SymbolsIterator` 类的功能。`SymbolsIterator` 的作用是**将一段文本分解成不同的“runs”，每个 run 中的字符具有相同的字体回退优先级**。简单来说，它负责识别文本中哪些部分应该被视为普通文本，哪些部分应该被视为 emoji 或其他特殊符号，以便在渲染时选择合适的字体。

以下是更详细的功能解释以及与 JavaScript、HTML、CSS 的关系：

**1. 功能：文本分解和字体回退优先级判断**

`SymbolsIterator` 的核心功能是遍历一段文本（UTF-16 编码），并将其分割成多个连续的片段（runs）。对于每个 run，`SymbolsIterator` 会确定一个 `FontFallbackPriority`，这个枚举值指示了该 run 中的字符应该优先使用哪种类型的字体进行渲染。

可能的 `FontFallbackPriority` 值包括但不限于：

* `kText`:  普通的文本字符。
* `kEmojiEmoji`:  表情符号（默认以彩色 emoji 渲染）。
* `kEmojiTextWithVS`:  带有 Variation Selector-15 (VS15, `U+FE0E`) 的 emoji，通常指示以文本形式渲染。
* `kEmojiEmojiWithVS`: 带有 Variation Selector-16 (VS16, `U+FE0F`) 的 emoji，通常指示以彩色 emoji 渲染。
* `kInvalid`:  无效的优先级。

**2. 与 JavaScript, HTML, CSS 的关系**

虽然这是一个 C++ 文件，直接在 Blink 引擎内部运行，但它的功能直接影响着 JavaScript, HTML, 和 CSS 在浏览器中的呈现效果：

* **JavaScript:**  JavaScript 可以操作 HTML 中的文本内容。当浏览器需要渲染这些文本时，Blink 引擎会使用类似 `SymbolsIterator` 的机制来分析文本。JavaScript 可以通过 DOM API 获取和修改文本内容，但底层如何将文本分解并决定字体回退，是由 Blink 引擎负责的。

    * **举例说明:**  假设 JavaScript 代码动态地向一个 HTML 元素中插入了一个包含 emoji 的字符串：`element.textContent = "Hello 🌍!";`  当浏览器渲染这个元素时，Blink 引擎会使用 `SymbolsIterator` 或类似的逻辑来识别 "Hello " 是普通文本，而 "🌍" 是一个 emoji，并分别赋予它们不同的字体回退优先级。

* **HTML:** HTML 定义了网页的结构和内容，其中包含大量的文本。浏览器解析 HTML 后，会形成 DOM 树，其中的文本节点需要被渲染。`SymbolsIterator` 的功能确保了 HTML 中不同类型的字符能够被正确地渲染出来。

    * **举例说明:**  考虑以下的 HTML 片段：`<p>This is text with an emoji: ❤️</p>`。当浏览器渲染这段 HTML 时，`SymbolsIterator` 会识别 "This is text with an emoji: " 为 `kText` 优先级，而 "❤️" 为 `kEmojiEmoji` 优先级。

* **CSS:** CSS 用于控制 HTML 元素的样式，包括字体。`SymbolsIterator` 确定的字体回退优先级会影响浏览器最终选择哪个字体来渲染文本。例如，可以设置一个 `font-family` 列表，浏览器会根据优先级依次尝试这些字体。如果一个字符被标记为 `kEmojiEmoji`，浏览器可能会优先尝试 emoji 字体。

    * **举例说明:**  假设 CSS 中有以下定义：
        ```css
        body {
            font-family: "Roboto", "Segoe UI Emoji", sans-serif;
        }
        ```
        当渲染包含 emoji 的文本时，如果 `SymbolsIterator` 将 emoji 标记为 `kEmojiEmoji`，浏览器会首先尝试使用 "Segoe UI Emoji" 字体来渲染这个 emoji。如果 "Segoe UI Emoji" 不可用，则会回退到 `sans-serif` 中定义的字体。

**3. 逻辑推理举例 (假设输入与输出)**

`SymbolsIteratorTest` 中的测试用例展示了 `SymbolsIterator` 的逻辑推理过程。例如：

* **假设输入:** 字符串 "a⌚b"
* **预期输出:**
    * Run 1:  "a", `FontFallbackPriority::kText`
    * Run 2:  "⌚", `FontFallbackPriority::kEmojiEmoji`
    * Run 3:  "b", `FontFallbackPriority::kText`

**推理:**  `SymbolsIterator` 会识别 "a" 和 "b" 是普通字母，赋予 `kText` 优先级。"⌚" 是一个时钟 emoji，赋予 `kEmojiEmoji` 优先级。

* **假设输入:** 字符串 "1️⃣" (数字 1 + Combining Enclosing Keycap)
* **预期输出:**
    * Run 1: "1️⃣", `FontFallbackPriority::kEmojiEmojiWithVS` (取决于 FontVariantEmoji feature 的状态，如果开启，则可能是 Emoji)

**推理:**  这是一个 emoji presentation sequence，应该以 emoji 形式渲染。

* **假设输入:** 字符串 "☂️" (雨伞 + Variation Selector-16)
* **预期输出:** "☂️", `FontFallbackPriority::kEmojiEmojiWithVS`

**推理:** Variation Selector-16 (U+FE0F) 通常强制以 emoji 形式渲染。

* **假设输入:** 字符串 "☂︎" (雨伞 + Variation Selector-15)
* **预期输出:** "☂︎", `FontFallbackPriority::kEmojiTextWithVS`

**推理:** Variation Selector-15 (U+FE0E) 通常强制以文本形式渲染（如果该 emoji 有文本表示）。

**4. 用户或编程常见的使用错误举例**

虽然 `SymbolsIterator` 是 Blink 引擎内部的实现，用户或开发者在使用 JavaScript, HTML, CSS 时，如果对字符的分类和渲染机制不了解，可能会遇到以下问题：

* **错误地假设所有字符都用相同的字体渲染:**  开发者可能没有考虑到 emoji 和其他特殊字符需要不同的字体支持。如果只设置了一个简单的 `font-family`，可能会导致 emoji 显示为方块或其他占位符。

    * **举例:**  一个网页只设置了 `font-family: Arial;`，当页面中出现 emoji 时，由于 Arial 字体不包含 emoji 字形，这些 emoji 将无法正常显示。

* **不理解 Variation Selectors 的作用:**  开发者可能不清楚 Variation Selectors 可以改变字符的渲染方式（文本或 emoji）。这可能导致他们意外地看到了文本形式的 emoji 或彩色 emoji。

    * **举例:**  开发者在文本中输入了 "U+2615 U+FE0E" (HOT BEVERAGE + VS15)，期望看到彩色咖啡杯 emoji，但由于 VS15 的存在，浏览器可能会渲染成黑白文本形式的咖啡杯。

* **对 ZWJ (Zero Width Joiner) 序列不熟悉:**  开发者可能不理解 ZWJ 序列是如何将多个字符组合成一个 emoji 的。如果他们尝试分割或操作 ZWJ 序列的中间部分，可能会导致 emoji 显示不正常。

    * **举例:**  开发者尝试将 "👩‍⚕️" (WOMAN HEALTH WORKER) 这个 emoji 按照字符分割，可能会得到 "👩" (WOMAN), ZWJ, "⚕️" (STAFF OF AESCULAPIUS)，而不是将其作为一个整体来处理。

* **在不支持某些新 Emoji 的旧系统或字体上显示:**  用户可能会在操作系统或浏览器不支持的 Emoji 版本上看到乱码或方块。这并非 `SymbolsIterator` 的错误，而是字体和系统支持的问题。

总而言之，`symbols_iterator_test.cc` 文件通过大量的测试用例，确保了 `SymbolsIterator` 能够正确地将文本分解成具有合适字体回退优先级的 runs，这对于在浏览器中正确渲染各种类型的字符（包括 emoji）至关重要。它的功能是底层渲染机制的一部分，直接影响着开发者使用 JavaScript, HTML, CSS 构建网页时的呈现效果。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/symbols_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/symbols_iterator.h"

#include <string>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font_variant_emoji.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

struct FallbackTestRun {
  std::string text;
  FontFallbackPriority font_fallback_priority;
};

struct FallbackExpectedRun {
  unsigned limit;
  FontFallbackPriority font_fallback_priority;

  FallbackExpectedRun(unsigned the_limit,
                      FontFallbackPriority the_font_fallback_priority)
      : limit(the_limit), font_fallback_priority(the_font_fallback_priority) {}
};

const bool FontVariantEmojiFlagValues[] = {true, false};

class SymbolsIteratorTest : public testing::Test {
 protected:
  void SetUp() override { ScopedFontVariantEmojiForTest scoped_feature(true); }

  void CheckRuns(const Vector<FallbackTestRun>& runs) {
    StringBuilder text;
    text.Ensure16Bit();
    Vector<FallbackExpectedRun> expect;
    for (auto& run : runs) {
      text.Append(String::FromUTF8(run.text.c_str()));
      expect.push_back(
          FallbackExpectedRun(text.length(), run.font_fallback_priority));
    }
    SymbolsIterator symbols_iterator(text.Span16());
    VerifyRuns(&symbols_iterator, expect);
  }

  void VerifyRuns(SymbolsIterator* symbols_iterator,
                  const Vector<FallbackExpectedRun>& expect) {
    unsigned limit;
    FontFallbackPriority font_fallback_priority;
    size_t run_count = 0;
    while (symbols_iterator->Consume(&limit, &font_fallback_priority)) {
      ASSERT_LT(run_count, expect.size());
      ASSERT_EQ(expect[run_count].limit, limit);
      ASSERT_EQ(expect[run_count].font_fallback_priority,
                font_fallback_priority);
      ++run_count;
    }
    ASSERT_EQ(expect.size(), run_count);
  }
};

class SymbolsIteratorWithFontVariantEmojiParamTest
    : public SymbolsIteratorTest,
      public testing::WithParamInterface<bool> {
  void SetUp() override {
    ScopedFontVariantEmojiForTest scoped_feature(GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(SymbolsIteratorTest,
                         SymbolsIteratorWithFontVariantEmojiParamTest,
                         testing::ValuesIn(FontVariantEmojiFlagValues));

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Empty) {
  String empty(g_empty_string16_bit);
  SymbolsIterator symbols_iterator(empty.Span16());
  unsigned limit = 0;
  FontFallbackPriority symbols_font = FontFallbackPriority::kInvalid;
  DCHECK(!symbols_iterator.Consume(&limit, &symbols_font));
  ASSERT_EQ(limit, 0u);
  ASSERT_EQ(symbols_font, FontFallbackPriority::kInvalid);
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Space) {
  CheckRuns({{" ", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Latin) {
  CheckRuns({{"Aa", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, BMPEmoji) {
  CheckRuns({{"⌚⌛⌚⌛⌚⌛⌚⌛", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, LatinColorEmojiTextEmoji) {
  CheckRuns({{"a", FontFallbackPriority::kText},
             {"⌚", FontFallbackPriority::kEmojiEmoji},
             {"☎", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, IgnoreVSInMath) {
  CheckRuns({{"⊆⊇⊈\U0000FE0E⊙⊚⊚", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, IgnoreVS15InText) {
  CheckRuns({{"abcdef\U0000FE0Eghji", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, IgnoreVS16InText) {
  CheckRuns({{"abcdef\U0000FE0Fghji", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, AllHexValuesText) {
  // Helps with detecting incorrect emoji pattern definitions which are
  // missing a \U000... prefix for example.
  CheckRuns({{"abcdef0123456789ABCDEF", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       NumbersAndHashNormalAndEmoji) {
  CheckRuns({{"0123456789#*", FontFallbackPriority::kText},
             {"0\uFE0F⃣1\uFE0F⃣2\uFE0F⃣3\uFE0F⃣4\uFE0F⃣5\uFE0F⃣6\uFE0F⃣7\uFE0F⃣8\uFE0F⃣9"
              "\uFE0F⃣*\uFE0F⃣",
              FontFallbackPriority::kEmojiEmojiWithVS},
             {"0123456789#*", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, VS16onDigits) {
  CheckRuns({{"#", FontFallbackPriority::kText},
             {"#\uFE0F\u20E3", FontFallbackPriority::kEmojiEmojiWithVS},
             {"#", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, VS15onDigits) {
  CheckRuns({{"#", FontFallbackPriority::kText},
             {"#\uFE0E\u20E3", FontFallbackPriority::kEmojiTextWithVS},
             {"#", FontFallbackPriority::kText}});
}

TEST_F(SymbolsIteratorTest, EmojiVS15AndVS16) {
  CheckRuns(
      {{"\U0001F642", FontFallbackPriority::kEmojiEmoji},
       {"\U0001F642\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
       {"\U0001F642\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS}});
}

TEST_F(SymbolsIteratorTest, EmojiVSSplitStartsWithText) {
  CheckRuns({{"abc", FontFallbackPriority::kText},
             {"\U00002614", FontFallbackPriority::kEmojiEmoji},
             {"\U00002603", FontFallbackPriority::kText},
             {"\U00002614\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS}});
}

TEST_F(SymbolsIteratorTest, EmojiVSSplitStartsWithEmoji) {
  CheckRuns(
      {{"\U00002614\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
       {"abc", FontFallbackPriority::kText},
       {"\U00002614\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
       {"\U00002614", FontFallbackPriority::kEmojiEmoji},
       {"\U00002614\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS}});
}

TEST_F(SymbolsIteratorTest, EmojiVSSplitWithExcessiveVS) {
  CheckRuns({{"\U00002603", FontFallbackPriority::kText},
             {"\U00002603\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
             {"\U00002614\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
             {"\U00002614", FontFallbackPriority::kEmojiEmoji}});
}

TEST_F(SymbolsIteratorTest, EmojiAndTextVSSplit) {
  CheckRuns({{"\U00002603", FontFallbackPriority::kText},
             {"\U00002603\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
             {"\U00002614\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
             {"\U00002614", FontFallbackPriority::kEmojiEmoji}});
}

TEST_F(SymbolsIteratorTest, EmojiTextVSSplit) {
  CheckRuns({{"\U00002614\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
             {"a\U00002603bc", FontFallbackPriority::kText},
             {"\U00002603\U0000FE0E\U00002614\U0000FE0E",
              FontFallbackPriority::kEmojiTextWithVS}});
}

TEST_F(SymbolsIteratorTest, ZWJWithVS) {
  // Variation selector 16 after ZWJ sequences is excessive, hence it should not
  // affect segmentation.
  // ZWJ sequences from the test below:
  // 26D3 FE0F 200D 1F4A5; RGI_Emoji_ZWJ_Sequence; broken chain (⛓️‍💥)
  // 1F469 200D 2764 FE0F 200D 1F48B 200D 1F468; RGI_Emoji_ZWJ_Sequence; kiss:
  // woman, man (👩‍❤️‍💋‍👨)
  // https://www.unicode.org/Public/emoji/15.1/emoji-zwj-sequences.txt
  CheckRuns({{"abc", FontFallbackPriority::kText},
             {"\U000026D3\U0000FE0F\U0000200D\U0001F4A5\U0000FE0F"
              "\U0001F469\U0000200D\U00002764\U0000FE0F\U0000200D\U0001F48B"
              "\U0000200D\U0001F468"
              "\U000026D3\U0000FE0F\U0000200D\U0001F4A5",
              FontFallbackPriority::kEmojiEmoji},
             {"\U0000FE0E", FontFallbackPriority::kText}});
}

TEST_F(SymbolsIteratorTest, MultipleMisplacedVS) {
  CheckRuns({
      {"\U0000FE0E\U0000FE0F", FontFallbackPriority::kText},
      {"\U0001F642\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
      {"\U0001F642\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
      {"\U0001F642\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
      {"\U0000FE0E\U0000FE0F", FontFallbackPriority::kText},
      {"\U0001F642\U0000FE0F", FontFallbackPriority::kEmojiEmojiWithVS},
      {"\U0001F642\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
      {"\U0000FE0E\U0000FE0F", FontFallbackPriority::kText},
  });
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, SingleFlag) {
  CheckRuns({{"🇺", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, CombiningCircle) {
  CheckRuns({{"◌́◌̀◌̈◌̂◌̄◌̊", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       CombiningEnclosingCircleBackslash) {
  CheckRuns({{"A⃠B⃠C⃠", FontFallbackPriority::kText},
             {"🚷🚯🚱🔞📵🚭🚫🎙⃠📸⃠🔫⃠",
              FontFallbackPriority::kEmojiEmoji},
             {"a⃠b⃠c⃠", FontFallbackPriority::kText}});
}

// TODO: Perhaps check for invalid country indicator combinations?

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, FlagsVsNonFlags) {
  CheckRuns({{"🇺🇸", FontFallbackPriority::kEmojiEmoji},  // "US"
             {"🇸abc", FontFallbackPriority::kText},
             {"🇺🇸", FontFallbackPriority::kEmojiEmoji},
             {"a🇿", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, EmojiVS15) {
  // A VS15 after the anchor must trigger text display.
  CheckRuns({{"⚓\U0000FE0E", FontFallbackPriority::kEmojiTextWithVS},
             {"⛵", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, EmojiZWSSequences) {
  CheckRuns(
      {{"👩‍👩‍👧‍👦👩‍❤️‍💋‍👨",
        FontFallbackPriority::kEmojiEmoji},
       {"abcd", FontFallbackPriority::kText},
       {"\U0001F469\U0000200D\U0001F469", FontFallbackPriority::kEmojiEmoji},
       {"\U0000200Defgh", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, AllEmojiZWSSequences) {
  // clang-format gets confused by Emojis, http://llvm.org/PR30530
  // clang-format off
  CheckRuns(
      {{"💏👩‍❤️‍💋‍👨👨‍❤️‍💋‍👨👩‍❤️‍💋‍👩💑👩‍❤️‍👨👨‍❤"
        "️"
        "‍👨👩‍❤️"
        "‍👩👪👨‍👩‍👦👨‍👩‍👧👨‍👩‍👧‍👦👨‍👩‍👦‍👦👨‍👩‍👧‍👧👨‍👨"
        "‍"
        "👦👨‍👨‍👧👨‍👨‍👧‍👦👨‍👨‍👦‍👦👨‍👨‍👧"
        "‍"
        "👧"
        "👩‍👩‍👦👩‍👩‍👧👩‍👩‍👧‍👦👩‍👩‍👦‍👦👩‍👩‍👧‍👧👁"
        "‍"
        "🗨",
        FontFallbackPriority::kEmojiEmoji}});
  // clang-format on
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, ModifierPlusGender) {
  CheckRuns({{"⛹🏻‍♂", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, TextMemberZwjSequence) {
  CheckRuns({{"👨‍⚕️", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       FacepalmCartwheelShrugModifierFemale) {
  CheckRuns({{"🤦‍♀🤸‍♀🤷‍♀🤷🏾‍♀",
              FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       AesculapiusMaleFemalEmoji) {
  // Emoji Data 4 has upgraded those three characters to Emoji.
  CheckRuns({{"a⚕♀♂", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, EyeSpeechBubble) {
  CheckRuns({{"👁‍🗨", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Modifier) {
  CheckRuns({{"👶🏿", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       DingbatsMiscSymbolsModifier) {
  CheckRuns({{"⛹🏻✍🏻✊🏼", FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, ExtraZWJPrefix) {
  CheckRuns({{"\U0000200D", FontFallbackPriority::kText},
             {"\U0001F469\U0000200D\U00002764\U0000FE0F\U0000200D\U0001F48B"
              "\U0000200D\U0001F468",
              FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, StrayZWJAndVS) {
  CheckRuns({{"\U0000200D\U0000FE0E\U0000FE0E\U0000FE0E\U0000200D\U0000200D",
              FontFallbackPriority::kText},
             {"\U0001F469\U0000200D\U00002764\U0000FE0F\U0000200D\U0001F48B"
              "\U0000200D\U0001F468",
              FontFallbackPriority::kEmojiEmoji},
             {"\U0000200D\U0000FE0E\U0000FE0E\U0000FE0E\U0000200D\U0000200D",
              FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Arrows) {
  CheckRuns({{"x→←x←↑↓→", FontFallbackPriority::kText}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, JudgePilot) {
  CheckRuns({{"👨‍⚖️👩‍⚖️👨🏼‍⚖️👩🏼‍⚖️",
              FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, EmojiPunctuationText) {
  CheckRuns({{"⁉⁉⁉⁈⁈⁈", FontFallbackPriority::kText}});
}

// Extracted from http://unicode.org/emoji/charts/emoji-released.html for Emoji
// v5.0, except for the subdivision-flag section.
// Before ICU 59 new emoji sequences and new single emoji are not detected as
// emoji type text and sequences get split up in the middle so that shaping
// cannot form the right glyph from the emoji font. Running this as one run in
// one test ensures that the new emoji form an unbroken emoji-type sequence.
TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest,
       Emoji5AdditionsExceptFlags) {
  CheckRuns(
      {{"\U0001F9D4\U0001F3FB\U0001F9D4\U0001F3FC\U0001F9D4\U0001F3FD"
        "\U0001F9D4\U0001F3FE\U0001F9D4\U0001F3FF\U0001F931\U0001F931"
        "\U0001F3FB\U0001F931\U0001F3FC\U0001F931\U0001F3FD\U0001F931"
        "\U0001F3FE\U0001F931\U0001F3FF\U0001F9D9\U0001F9D9\U0001F3FB"
        "\U0001F9D9\U0001F3FC\U0001F9D9\U0001F3FD\U0001F9D9\U0001F3FE"
        "\U0001F9D9\U0001F3FF\U0001F9D9\U0000200D\U00002640\U0000FE0F"
        "\U0001F9D9\U0001F3FB\U0000200D\U00002640\U0000FE0F\U0001F9D9"
        "\U0001F3FC\U0000200D\U00002640\U0000FE0F\U0001F9D9\U0001F3FD"
        "\U0000200D\U00002640\U0000FE0F\U0001F9D9\U0001F3FE\U0000200D"
        "\U00002640\U0000FE0F\U0001F9D9\U0001F3FF\U0000200D\U00002640"
        "\U0000FE0F\U0001F9D9\U0000200D\U00002642\U0000FE0F\U0001F9D9"
        "\U0001F3FB\U0000200D\U00002642\U0000FE0F\U0001F9D9\U0001F3FC"
        "\U0000200D\U00002642\U0000FE0F\U0001F9D9\U0001F3FD\U0000200D"
        "\U00002642\U0000FE0F\U0001F9D9\U0001F3FE\U0000200D\U00002642"
        "\U0000FE0F\U0001F9D9\U0001F3FF\U0000200D\U00002642\U0000FE0F"
        "\U0001F9DA\U0001F9DA\U0001F3FB\U0001F9DA\U0001F3FC\U0001F9DA"
        "\U0001F3FD\U0001F9DA\U0001F3FE\U0001F9DA\U0001F3FF\U0001F9DA"
        "\U0000200D\U00002640\U0000FE0F\U0001F9DA\U0001F3FB\U0000200D"
        "\U00002640\U0000FE0F\U0001F9DA\U0001F3FC\U0000200D\U00002640"
        "\U0000FE0F\U0001F9DA\U0001F3FD\U0000200D\U00002640\U0000FE0F"
        "\U0001F9DA\U0001F3FE\U0000200D\U00002640\U0000FE0F\U0001F9DA"
        "\U0001F3FF\U0000200D\U00002640\U0000FE0F\U0001F9DA\U0000200D"
        "\U00002642\U0000FE0F\U0001F9DA\U0001F3FB\U0000200D\U00002642"
        "\U0000FE0F\U0001F9DA\U0001F3FC\U0000200D\U00002642\U0000FE0F"
        "\U0001F9DA\U0001F3FD\U0000200D\U00002642\U0000FE0F\U0001F9DA"
        "\U0001F3FE\U0000200D\U00002642\U0000FE0F\U0001F9DA\U0001F3FF"
        "\U0000200D\U00002642\U0000FE0F\U0001F9DB\U0001F9DB\U0001F3FB"
        "\U0001F9DB\U0001F3FC\U0001F9DB\U0001F3FD\U0001F9DB\U0001F3FE"
        "\U0001F9DB\U0001F3FF\U0001F9DB\U0000200D\U00002640\U0000FE0F"
        "\U0001F9DB\U0001F3FB\U0000200D\U00002640\U0000FE0F\U0001F9DB"
        "\U0001F3FC\U0000200D\U00002640\U0000FE0F\U0001F9DB\U0001F3FD"
        "\U0000200D\U00002640\U0000FE0F\U0001F9DB\U0001F3FE\U0000200D"
        "\U00002640\U0000FE0F\U0001F9DB\U0001F3FF\U0000200D\U00002640"
        "\U0000FE0F\U0001F9DB\U0000200D\U00002642\U0000FE0F\U0001F9DB"
        "\U0001F3FB\U0000200D\U00002642\U0000FE0F\U0001F9DB\U0001F3FC"
        "\U0000200D\U00002642\U0000FE0F\U0001F9DB\U0001F3FD\U0000200D"
        "\U00002642\U0000FE0F\U0001F9DB\U0001F3FE\U0000200D\U00002642"
        "\U0000FE0F\U0001F9DB\U0001F3FF\U0000200D\U00002642\U0000FE0F"
        "\U0001F9DC\U0001F9DC\U0001F3FB\U0001F9DC\U0001F3FC\U0001F9DC"
        "\U0001F3FD\U0001F9DC\U0001F3FE\U0001F9DC\U0001F3FF\U0001F9DC"
        "\U0000200D\U00002640\U0000FE0F\U0001F9DC\U0001F3FB\U0000200D"
        "\U00002640\U0000FE0F\U0001F9DC\U0001F3FC\U0000200D\U00002640"
        "\U0000FE0F\U0001F9DC\U0001F3FD\U0000200D\U00002640\U0000FE0F"
        "\U0001F9DC\U0001F3FE\U0000200D\U00002640\U0000FE0F\U0001F9DC"
        "\U0001F3FF\U0000200D\U00002640\U0000FE0F\U0001F9DC\U0000200D"
        "\U00002642\U0000FE0F\U0001F9DC\U0001F3FB\U0000200D\U00002642"
        "\U0000FE0F\U0001F9DC\U0001F3FC\U0000200D\U00002642\U0000FE0F"
        "\U0001F9DC\U0001F3FD\U0000200D\U00002642\U0000FE0F\U0001F9DC"
        "\U0001F3FE\U0000200D\U00002642\U0000FE0F\U0001F9DC\U0001F3FF"
        "\U0000200D\U00002642\U0000FE0F\U0001F9DD\U0001F9DD\U0001F3FB"
        "\U0001F9DD\U0001F3FC\U0001F9DD\U0001F3FD\U0001F9DD\U0001F3FE"
        "\U0001F9DD\U0001F3FF\U0001F9DD\U0000200D\U00002640\U0000FE0F"
        "\U0001F9DD\U0001F3FB\U0000200D\U00002640\U0000FE0F\U0001F9DD"
        "\U0001F3FC\U0000200D\U00002640\U0000FE0F\U0001F9DD\U0001F3FD"
        "\U0000200D\U00002640\U0000FE0F\U0001F9DD\U0001F3FE\U0000200D"
        "\U00002640\U0000FE0F\U0001F9DD\U0001F3FF\U0000200D\U00002640"
        "\U0000FE0F\U0001F9DD\U0000200D\U00002642\U0000FE0F\U0001F9DD"
        "\U0001F3FB\U0000200D\U00002642\U0000FE0F\U0001F9DD\U0001F3FC"
        "\U0000200D\U00002642\U0000FE0F\U0001F9DD\U0001F3FD\U0000200D"
        "\U00002642\U0000FE0F\U0001F9DD\U0001F3FE\U0000200D\U00002642"
        "\U0000FE0F\U0001F9DD\U0001F3FF\U0000200D\U00002642\U0000FE0F"
        "\U0001F9DE\U0001F9DE\U0000200D\U00002640\U0000FE0F\U0001F9DE"
        "\U0000200D\U00002642\U0000FE0F\U0001F9DF\U0001F9DF\U0000200D"
        "\U00002640\U0000FE0F\U0001F9DF\U0000200D\U00002642\U0000FE0F"
        "\U0001F9D6\U0001F9D6\U0001F3FB\U0001F9D6\U0001F3FC\U0001F9D6"
        "\U0001F3FD\U0001F9D6\U0001F3FE\U0001F9D6\U0001F3FF\U0001F9D6"
        "\U0000200D\U00002640\U0000FE0F\U0001F9D6\U0001F3FB\U0000200D"
        "\U00002640\U0000FE0F\U0001F9D6\U0001F3FC\U0000200D\U00002640"
        "\U0000FE0F\U0001F9D6\U0001F3FD\U0000200D\U00002640\U0000FE0F"
        "\U0001F9D6\U0001F3FE\U0000200D\U00002640\U0000FE0F\U0001F9D6"
        "\U0001F3FF\U0000200D\U00002640\U0000FE0F\U0001F9D6\U0000200D"
        "\U00002642\U0000FE0F\U0001F9D6\U0001F3FB\U0000200D\U00002642"
        "\U0000FE0F\U0001F9D6\U0001F3FC\U0000200D\U00002642\U0000FE0F"
        "\U0001F9D6\U0001F3FD\U0000200D\U00002642\U0000FE0F\U0001F9D6"
        "\U0001F3FE\U0000200D\U00002642\U0000FE0F\U0001F9D6\U0001F3FF"
        "\U0000200D\U00002642\U0000FE0F\U0001F9D7\U0001F9D7\U0001F3FB"
        "\U0001F9D7\U0001F3FC\U0001F9D7\U0001F3FD\U0001F9D7\U0001F3FE"
        "\U0001F9D7\U0001F3FF\U0001F9D7\U0000200D\U00002640\U0000FE0F"
        "\U0001F9D7\U0001F3FB\U0000200D\U00002640\U0000FE0F\U0001F9D7"
        "\U0001F3FC\U0000200D\U00002640\U0000FE0F\U0001F9D7\U0001F3FD"
        "\U0000200D\U00002640\U0000FE0F\U0001F9D7\U0001F3FE\U0000200D"
        "\U00002640\U0000FE0F\U0001F9D7\U0001F3FF\U0000200D\U00002640"
        "\U0000FE0F\U0001F9D7\U0000200D\U00002642\U0000FE0F\U0001F9D7"
        "\U0001F3FB\U0000200D\U00002642\U0000FE0F\U0001F9D7\U0001F3FC"
        "\U0000200D\U00002642\U0000FE0F\U0001F9D7\U0001F3FD\U0000200D"
        "\U00002642\U0000FE0F\U0001F9D7\U0001F3FE\U0000200D\U00002642"
        "\U0000FE0F\U0001F9D7\U0001F3FF\U0000200D\U00002642\U0000FE0F"
        "\U0001F9D8\U0001F9D8\U0001F3FB\U0001F9D8\U0001F3FC\U0001F9D8"
        "\U0001F3FD\U0001F9D8\U0001F3FE\U0001F9D8\U0001F3FF\U0001F9D8"
        "\U0000200D\U00002640\U0000FE0F\U0001F9D8\U0001F3FB\U0000200D"
        "\U00002640\U0000FE0F\U0001F9D8\U0001F3FC\U0000200D\U00002640"
        "\U0000FE0F\U0001F9D8\U0001F3FD\U0000200D\U00002640\U0000FE0F"
        "\U0001F9D8\U0001F3FE\U0000200D\U00002640\U0000FE0F\U0001F9D8"
        "\U0001F3FF\U0000200D\U00002640\U0000FE0F\U0001F9D8\U0000200D"
        "\U00002642\U0000FE0F\U0001F9D8\U0001F3FB\U0000200D\U00002642"
        "\U0000FE0F\U0001F9D8\U0001F3FC\U0000200D\U00002642\U0000FE0F"
        "\U0001F9D8\U0001F3FD\U0000200D\U00002642\U0000FE0F\U0001F9D8"
        "\U0001F3FE\U0000200D\U00002642\U0000FE0F\U0001F9D8\U0001F3FF"
        "\U0000200D\U00002642\U0000FE0F\U0001F91F\U0001F91F\U0001F3FB"
        "\U0001F91F\U0001F3FC\U0001F91F\U0001F3FD\U0001F91F\U0001F3FE"
        "\U0001F91F\U0001F3FF\U0001F932\U0001F932\U0001F3FB\U0001F932"
        "\U0001F3FC\U0001F932\U0001F3FD\U0001F932\U0001F3FE\U0001F932"
        "\U0001F3FF\U0001F9E0\U0001F9E1\U0001F9E3\U0001F9E4\U0001F9E5"
        "\U0001F9E6\U0001F9E2\U0001F993\U0001F992\U0001F994\U0001F995"
        "\U0001F996\U0001F997\U0001F965\U0001F966\U0001F968\U0001F969"
        "\U0001F96A\U0001F963\U0001F96B\U0001F95F\U0001F960\U0001F961"
        "\U0001F967\U0001F964\U0001F962\U0001F6F8\U0001F6F7\U0001F94C",
        FontFallbackPriority::kEmojiEmoji}});
}

TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, EmojiSubdivisionFlags) {
  CheckRuns({{"\U0001F3F4\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073"
              "\U000E007F\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063"
              "\U000E0074\U000E007F\U0001F3F4",
              FontFallbackPriority::kEmojiEmoji},
             // Tag sequences on their own do not mean they're emoji.
             {"\U000E0067\U000E0062", FontFallbackPriority::kText}});
}

// Extracted from http://unicode.org/emoji/charts/emoji-released.html for Emoji
// v11, removed U+265F Chess Pawn and U+267E as they do not have default emoji
// presentation.
TEST_P(SymbolsIteratorWithFontVariantEmojiParamTest, Emoji11Additions) {
  CheckRuns(
      {{"\U0001F970\U0001F975\U0001F976\U0001F973\U0001F974\U0001F97A"
        "\U0001F468\U0000200D\U0001F9B0\U0001F468\U0001F3FB\U0000200D"
        "\U0001F9B0\U0001F468\U0001F3FC\U0000200D\U0001F9B0\U0001F468"
        "\U0001F3FD\U0000200D\U0001F9B0\U0001F468\U0001F3FE\U0000200D"
        "\U0001F9B0\U0001F468\U0001F3FF\U0000200D\U0001F9B0\U0001F468"
        "\U0000200D\U0001F9B1\U0001F468\U0001F3FB\U0000200D\U0001F9B1"
        "\U0001F468\U0001F3FC\U0000200D\U0001F9B1\U0001F468\U0001F3FD"
        "\U0000200D\U0001F9B1\U0001F468\U0001F3FE\U0000200D\U0001F9B1"
        "\U0001F468\U0001F3FF\U0000200D\U0001F9B1\U0001F468\U0000200D"
        "\U0001F9B3\U0001F468\U0001F3FB\U0000200D\U0001F9B3\U0001F468"
        "\U0001F3FC\U0000200D\U0001F9B3\U0001F468\U0001F3FD\U0000200D"
        "\U0001F9B3\U0001F468\U0001F3FE\U0000200D\U0001F9B3\U0001F468"
        "\U0001F3FF\U0000200D\U0001F9B3\U0001F468\U0000200D\U0001F9B2"
        "\U0001F468\U0001F3FB\U0000200D\U0001F9B2\U0001F468\U0001F3FC"
        "\U0000200D\U0001F9B2\U0001F468\U0001F3FD\U0000200D\U0001F9B2"
        "\U0001F468\U0001F3FE\U0000200D\U0001F9B2\U0001F468\U0001F3FF"
        "\U0000200D\U0001F9B2\U0001F469\U0000200D\U0001F9B0\U0001F469"
        "\U0001F3FB\U0000200D\U0001F9B0\U0001F469\U0001F3FC\U0000200D"
        "\U0001F9B0\U0001F469\U0001F3FD\U0000200D\U0001F9B0\U0001F469"
        "\U0001F3FE\U0000200D\U0001F9B0\U0001F469\U0001F3FF\U0000200D"
        "\U0001F9B0\U0001F469\U0000200D\U0001F9B1\U0001F469\U0001F3FB"
        "\U0000200D\U0001F9B1\U0001F469\U0001F3FC\U0000200D\U0001F9B1"
        "\U0001F469\U0001F3FD\U0000200D\U0001F9B1\U0001F469\U0001F3FE"
        "\U0000200D\U0001F9B1\U0001F469\U0001F3FF\U0000200D\U0001F9B1"
        "\U0001F469\U0000200D\U0001F9B3\U0001F469\U0001F3FB\U0000200D"
        "\U0001F9B3\U0001F469\U0001F3FC\U0000200D\U0001F9B3\U0001F469"
        "\U0001F3FD\U0000200D\U0001F9B3\U0001F469\U0001F3FE\U0000200D"
        "\U0001F9B3\U0001F469\U0001F3FF\U0000200D\U0001F9B3\U0001F469"
        "\U0000200D\U0001F9B2\U0001F469\U0001F3FB\U0000200D\U0001F9B2"
        "\U0001F469\U0001F3FC\U0000200D\U0001F9B2\U0001F469\U0001F3FD"
        "\U0000200D\U0001F9B2\U0001F469\U0001F3FE\U0000200D\U0001F9B2"
        "\U0001F469\U0001F3FF\U0000200D\U0001F9B2\U0001F9B8\U0001F9B8"
        "\U0001F3FB\U0001F9B8\U0001F3FC\U0001F9B8\U0001F3FD\U0001F9B8"
        "\U0001F3FE\U0001F9B8\U0001F3FF\U0001F9B8\U0000200D\U00002640"
        "\U0000FE0F\U0001F9B8\U0001F3FB\U0000200D\U00002640\U0000FE0F"
        "\U0001F9B8\U0001F3FC\U0000200D\U00002640\U0000FE0F\U0001F9B8"
        "\U0001F3FD\U0000200D\U00002640\U0000FE0F\U0001F9B8\U0001F3FE"
        "\U0000200D\U00002640\U0000FE0F\U0001F9B8\U0001F3FF\U0000200D"
        "\U00002640\U0000FE0F\U0001F9B8\U0000200D\U00002642\U0000FE0F"
        "\U0001F9B8\U0001F3FB\U0000200D\U00002642\U0000FE0F\U0001F9B8"
        "\U0001F3FC\U0000200D\U00002642\U0000FE0F\U0001F9B8\U0001F3FD"
        "\U0000200D\U00002642\U0000FE0F\U0001F9B8\U0001F3FE\U0000200D"
        "\U00002642\U0000FE0F\U0001F9B8\U0001F3FF\U0000200D\U00002642"
        "\U0000FE0F\U0001F9B9\U0001F9B9\U0001F3FB\U0001F9B9\U0001F3FC"
        "\U0001F9B9\U0001F3FD\U0001F9B9\U0001F3FE\U0001F9B9\U0001F3FF"
        "\U0001F9B9\U0000200D\U00002640\U0000FE0F\U0001F9B9\U0001F3FB"
        "\U0000200D\U00002640\U0000FE0F\U0001F9B9\U0001F3FC\U0000200D"
        "\U00002640\U0000FE0F\U0001F9B9\U0001F3FD\U0000200D\U00002640"
        "\U0000FE0F\U0001F9B9\U0001F3FE\U0000200D\U00002640\U0000FE0F"
        "\U0001F9B9\U0001F3FF\U0000200D\U00002640\U0000FE0F\U0001F9B9"
        "\U0000200D\U00002642\U0000FE0F\U0001F9B9\U0001F3FB\U0000200D"
        "\U00002642\U0000FE0F\U0001F9B9\U0001F3FC\U0000200D\U00002642"
        "\U0000FE0F\U0001F9B9\U0001F3FD\U0000200D\U00002642\U0000FE0F"
        "\U0001F9B9\U0001F3FE\U0000200D\U00002642\U0000FE0F\U0001F9B9"
        "\U0001F3FF\U0000200D\U00002642\U0000FE0F\U0001F9B5\U0001F9B5"
        "\U0001F3FB\U0001F9B5\U0001F3FC\U0001F9B5\U0001F3FD\U0001F9B5"
        "\U0001F3FE\U0001F9B5\U0001F3FF\U0001F9B6\U0001F9B6\U0001F3FB"
        "\U0001F9B6\U0001F3FC\U0001F9B6\U0001F3FD\U0001F9B6\U0001F3FE"
        "\U0001F9B6\U0001F3FF\U0001F9B4\U0001F9B7\U0001F9B0\U0001F9B1"
        "\U0001F9B3\U0001F9B2\U0001F97D\U0001F97C\U0001F97E\U0001F97F"
        "\U0001F99D\U0001F999\U0001F99B\U0001F998\U0001F9A1\U0001F9A2"
        "\U0001F99A\U0001F99C\U0001F99E\U0001F99F\U0001F9A0\U0001F96D"
        "\U0001F96C\U0001F96F\U0001F9C2\U0001F96E\U0001F9C1\U0001F9ED"
        "\U0001F9F1\U0001F6F9\U0001F9F3\U0001F9E8\U0001F9E7\U0001F94E"
        "\U0001F94F\U0001F94D\U0001F9FF\U0001F9E9\U0001F9F8\U0001F9F5"
        "\U0001F9F6\U0001F9EE\U0001F9FE\U0001F9F0\U0001F9F2\U0001F9EA"
        "\U0001F9EB\U0001F9EC\U0001F9F4\U0001F9F7\U0001F9F9\U0001F9FA"
        "\U0001F9FB\U0001F9FC\U0001F9FD\U0001F9EF\U0001F3F4\U0000200D"
        "\U00002620\U0000FE0F",
        FontFallbackPriority::kEmojiEmoji}});
}

}  // namespace blink

"""

```
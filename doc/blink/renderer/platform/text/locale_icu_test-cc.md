Response:
My thought process to analyze the C++ test file and generate the comprehensive explanation would be as follows:

1. **Understand the Purpose:** The file name `locale_icu_test.cc` immediately suggests this is a test file specifically for the `LocaleICU` class. The `.cc` extension confirms it's C++ code. The `test` suffix indicates it uses a testing framework.

2. **Identify the Testing Framework:** The inclusion of `testing/gtest/include/gtest/gtest.h` tells me this file uses Google Test (gtest). This is a standard C++ testing framework.

3. **Analyze the Includes:**
    * `third_party/blink/renderer/platform/text/locale_icu.h`: This is the key include. It confirms that the code being tested is the `LocaleICU` class.
    * `<unicode/uvernum.h>`: This suggests interaction with ICU (International Components for Unicode) library, which is consistent with the file name and the concept of locale handling. ICU is a widely used library for internationalization.
    * `<memory>`: Used for smart pointers like `std::unique_ptr`.
    * `third_party/blink/renderer/platform/wtf/text/string_builder.h`:  Indicates the use of Blink's string building utility, likely for creating formatted output in the tests.

4. **Examine the Test Class Structure:**
    * `class LocaleICUTest : public testing::Test`: This defines the test fixture. Tests are grouped under this class. The `public testing::Test` part is gtest syntax.
    * **Helper Class `Labels`:** This inner class is a utility for comparing and representing vectors of strings, specifically for labels (like AM/PM). The `operator==` and `ToString` are the key methods.
    * **Protected Helper Methods:** The `protected` section contains several methods that simplify creating `LocaleICU` objects and accessing specific functionalities like `MonthFormat`, `TimeFormat`, `ShortTimeFormat`, and accessing month labels and AM/PM labels. These methods take a locale string as input. The use of `std::make_unique<LocaleICU>(locale_string)` confirms the creation and interaction with the `LocaleICU` class. The `IsRTL` method is also a key function being tested.

5. **Analyze Individual Tests:**  Each `TEST_F(LocaleICUTest, ...)` macro defines an individual test case. I need to understand what each test is verifying:
    * `isRTL`: Tests whether the `IsRTL` method correctly identifies right-to-left locales (like Arabic).
    * `monthFormat`: Checks the formatted string for the month, comparing against expected outputs for different locales (US English, French, Japanese). Notice the `.Utf8()` calls, indicating handling of potentially non-ASCII characters.
    * `localizedDateFormatText`, `localizedShortDateFormatText`:  Test the output format for full and short time formats for different locales.
    * `standAloneMonthLabels`, `shortMonthLabels`: Verify the full and abbreviated month names for different locales and specific month indices. The `#if U_ICU_VERSION_MAJOR_NUM >= 54` block highlights that the expected output might change based on the ICU library version, which is important for understanding potential inconsistencies.
    * `timeAMPMLabels`: Checks the AM/PM labels for different locales.
    * `localizedDecimalSeparator`: Tests the character used as the decimal separator in different locales.
    * `reversible`: This is a more complex test involving number formatting and parsing. The `TestNumberIsReversible` helper function suggests a round-trip test: convert a number to a localized format and then back to the original format, ensuring they match. The test cases cover various scenarios, including negative numbers and different decimal separators. The `TestNumbers` helper function runs the reversible test for several major locales.

6. **Identify Connections to Web Technologies:**  Based on the tested functionalities, I can deduce the relationships to JavaScript, HTML, and CSS:
    * **JavaScript:** The `LocaleICU` class likely underlies JavaScript's internationalization APIs (`Intl` object). Formatting dates, times, and numbers in JavaScript relies on locale-specific data.
    * **HTML:**  HTML's `lang` attribute influences how content is rendered. The RTL testing is directly relevant to how text direction is handled in HTML. Input types like `<input type="number">` and `<input type="date">` might implicitly use locale information for formatting and parsing.
    * **CSS:** CSS logical properties (e.g., `margin-inline-start`) are influenced by text direction, making the RTL checks relevant. While CSS doesn't directly format dates or numbers, it styles content that might be formatted using locale-specific rules.

7. **Infer Logical Reasoning and Assumptions:** The tests make assumptions about the correct output for different locales based on the ICU library's behavior. The tests use hardcoded expected values. The conditional logic based on ICU version shows awareness of potential API changes. The reversible number tests assume that the conversion process should be lossless.

8. **Identify Potential User/Programming Errors:**
    * **Incorrect Locale Strings:**  Passing invalid locale strings to `LocaleICU` could lead to unexpected behavior or errors. The tests implicitly check this by using valid strings and sometimes explicitly testing with `"**invalid**"`.
    * **Assuming Consistent Formatting:** Developers might incorrectly assume that number or date formats are consistent across all locales without using the appropriate internationalization APIs.
    * **Ignoring RTL:** Failing to handle right-to-left languages properly can lead to layout issues.
    * **Version Dependencies:** Code that relies on specific ICU versions might break when the underlying library is updated, as demonstrated by the version-specific checks in the tests.

9. **Structure the Explanation:** Organize the findings into logical sections: File Functionality, Relation to Web Technologies, Logical Reasoning, User/Programming Errors, and Assumptions. Use clear and concise language, providing examples where relevant. Use bullet points and code formatting to improve readability.

By following this structured approach, I can systematically analyze the code and generate a comprehensive and accurate explanation of its purpose and implications. The key is to understand the purpose of each part of the code and connect it back to the broader context of web development and internationalization.
这个文件 `blink/renderer/platform/text/locale_icu_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `LocaleICU` 类的各种功能**。`LocaleICU` 类负责处理与 **国际化（i18n）和本地化（l10n）** 相关的操作，例如获取特定语言环境下的日期、时间、数字的格式，判断文本方向（从左到右或从右到左），以及获取月份名称等信息。

**具体功能列举:**

这个测试文件通过使用 Google Test 框架，对 `LocaleICU` 类的以下功能进行了测试：

1. **判断文本方向 (IsRTL):**  测试 `IsRTL()` 方法是否能正确判断一个语言环境是否为从右到左的语言。
2. **获取月份格式 (MonthFormat):** 测试 `MonthFormat()` 方法是否能返回指定语言环境下的月份格式字符串。
3. **获取本地化日期格式 (LocalizedDateFormatText):** 测试 `TimeFormat()` 方法是否能返回指定语言环境下的完整时间格式字符串。
4. **获取本地化短日期格式 (LocalizedShortDateFormatText):** 测试 `ShortTimeFormat()` 方法是否能返回指定语言环境下的简短时间格式字符串。
5. **获取完整月份名称 (StandAloneMonthLabel):** 测试 `StandAloneMonthLabels()` 方法是否能返回指定语言环境下的完整月份名称。
6. **获取简短月份名称 (ShortMonthLabel 和 ShortStandAloneMonthLabel):** 测试 `ShortMonthLabels()` 和 `ShortStandAloneMonthLabels()` 方法是否能返回指定语言环境下的简短月份名称。
7. **获取 AM/PM 标签 (TimeAMPMLabels):** 测试 `TimeAMPMLabels()` 方法是否能返回指定语言环境下的 AM 和 PM 标签。
8. **获取本地化的小数点分隔符 (localizedDecimalSeparator):** 测试 `LocalizedDecimalSeparator()` 方法是否能返回指定语言环境下的小数点分隔符。
9. **数字的本地化和反本地化 (ConvertToLocalizedNumber 和 ConvertFromLocalizedNumber):** 测试将数字转换为本地化格式以及从本地化格式转换回原始数字的功能，确保转换是可逆的。

**与 JavaScript, HTML, CSS 的关系:**

`LocaleICU` 类是 Blink 引擎实现国际化功能的基础，它为上层（例如 JavaScript 引擎 V8）提供了本地化服务。因此，这个测试文件与 JavaScript, HTML, CSS 的功能有密切关系：

* **JavaScript:**
    * **`Intl` 对象:** JavaScript 的 `Intl` 对象提供了国际化 API，用于处理日期、时间、数字的格式化，以及文本的排序和比较。`LocaleICU` 提供的功能正是 `Intl` 对象在 Blink 引擎内部的实现基础。
    * **例子:** 当 JavaScript 代码中使用 `Intl.DateTimeFormat('ja-JP').format(new Date())` 时，Blink 引擎会调用 `LocaleICU` 的相关方法来获取日本的日期格式并进行格式化。
    * **假设输入与输出:**
        * **假设输入 (JavaScript):** `new Intl.NumberFormat('fr-FR').format(1234.56)`
        * **对应的 `LocaleICU` 功能:** `ConvertToLocalizedNumber` 方法会被调用，传入数字 "1234.56" 和法语 (fr-FR) 的 locale 信息。
        * **预期输出 (基于测试):**  `LocaleICUTest` 中 `localizedDecimalSeparator` 的测试表明法语的小数点分隔符是逗号，因此预期的本地化输出可能是 "1 234,56" (空格作为千位分隔符，逗号作为小数点分隔符)。

* **HTML:**
    * **`lang` 属性:** HTML 的 `lang` 属性用于指定元素的语言。浏览器会根据 `lang` 属性选择合适的字体、排版方式以及本地化格式。
    * **文本方向:**  对于 `dir="rtl"` 的元素，浏览器会根据语言环境的文本方向来渲染文本。`LocaleICUTest` 中 `isRTL` 的测试直接关系到浏览器如何解析和应用 HTML 的 `lang` 属性。
    * **例子:** 当 HTML 中有 `<p lang="ar">مرحبا</p>` 时，浏览器会调用 `LocaleICU` 的 `IsRTL` 方法来判断阿拉伯语是 RTL 语言，从而将文本从右向左渲染。

* **CSS:**
    * **逻辑属性:** CSS 的逻辑属性（如 `margin-inline-start`, `border-inline-end`）会根据文本方向进行调整。`LocaleICU` 提供的文本方向信息是浏览器实现这些逻辑属性的基础。
    * **例子:**  如果一个元素的 `lang` 属性设置为阿拉伯语 (`ar`)，并且使用了 `margin-inline-start: 10px;`，那么在渲染时，浏览器会根据 `LocaleICU` 返回的 RTL 信息，将这个样式应用到元素的右侧（而不是左侧）。

**逻辑推理的假设输入与输出:**

假设我们想测试 `LocaleICU` 获取日语月份名称的功能：

* **假设输入 (C++ 测试):** 调用 `StandAloneMonthLabel("ja_JP", 0)`
* **对应的 `LocaleICU` 功能:** `LocaleICU` 类内部会使用 ICU 库来获取日语 (ja_JP) 环境下的第一个月份（索引为 0）的完整名称。
* **预期输出 (基于测试):** `LocaleICUTest` 中 `standAloneMonthLabels` 的测试表明，日语的第一个月是 "1月" (UTF-8 编码为 `\xE6\x9C\x88`)。

**用户或编程常见的使用错误举例:**

1. **假设所有语言都使用相同的日期/时间格式:**
   * **错误示例 (JavaScript):**  假设所有用户都习惯 "MM/DD/YYYY" 格式，直接使用字符串拼接来格式化日期，而没有使用 `Intl.DateTimeFormat`。
   * **后果:**  对于使用 "DD/MM/YYYY" 或 "YYYY-MM-DD" 等格式的地区，显示的日期会不正确或难以理解。

2. **忽略文本方向:**
   * **错误示例 (CSS/HTML):**  在设计用户界面时，没有考虑到从右到左的语言，导致布局错乱，例如导航栏跑到右边，文本截断等。
   * **后果:**  RTL 用户体验差，难以阅读和操作。

3. **硬编码字符串或格式:**
   * **错误示例 (JavaScript):**  在代码中直接使用英文的月份名称（例如 "January"）来显示日期。
   * **后果:**  当用户使用其他语言时，界面上的月份名称不会本地化。

4. **错误地处理数字格式:**
   * **错误示例 (JavaScript):**  假设所有地区都使用点号作为小数点分隔符，并使用 `parseFloat()` 处理用户输入的数字。
   * **后果:**  对于使用逗号作为小数点分隔符的地区，`parseFloat()` 无法正确解析用户输入。

5. **没有进行充分的国际化测试:**
   * **错误示例:**  开发完成后只在英文环境下进行测试，没有考虑到其他语言和文化习惯。
   * **后果:**  上线后可能会出现大量的本地化问题，需要紧急修复。

总而言之，`blink/renderer/platform/text/locale_icu_test.cc` 这个文件通过详尽的测试用例，确保了 Blink 引擎的 `LocaleICU` 类能够正确地处理各种与国际化和本地化相关的需求，这对于构建支持多语言的 Web 应用至关重要。它间接保证了 JavaScript 的国际化 API 的正确性，并为浏览器正确渲染 HTML 和应用 CSS 样式提供了基础。

### 提示词
```
这是目录为blink/renderer/platform/text/locale_icu_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/text/locale_icu.h"

#include <unicode/uvernum.h>
#include <memory>
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class LocaleICUTest : public testing::Test {
 public:
  // Labels class is used for printing results in EXPECT_EQ macro.
  class Labels {
   public:
    Labels(const Vector<String> labels) : labels_(labels) {}

    // FIXME: We should use Vector<T>::operator==() if it works.
    bool operator==(const Labels& other) const {
      if (labels_.size() != other.labels_.size())
        return false;
      for (unsigned index = 0; index < labels_.size(); ++index) {
        if (labels_[index] != other.labels_[index])
          return false;
      }
      return true;
    }

    String ToString() const {
      StringBuilder builder;
      builder.Append("labels(");
      for (unsigned index = 0; index < labels_.size(); ++index) {
        if (index)
          builder.Append(", ");
        builder.Append('"');
        builder.Append(labels_[index]);
        builder.Append('"');
      }
      builder.Append(')');
      return builder.ToString();
    }

   private:
    Vector<String> labels_;
  };

 protected:
  Labels LabelsFromTwoElements(const String& element1, const String& element2) {
    Vector<String> labels = Vector<String>();
    labels.push_back(element1);
    labels.push_back(element2);
    return Labels(labels);
  }

  String MonthFormat(const char* locale_string) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->MonthFormat();
  }

  String LocalizedDateFormatText(const char* locale_string) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->TimeFormat();
  }

  String LocalizedShortDateFormatText(const char* locale_string) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->ShortTimeFormat();
  }

  String ShortMonthLabel(const char* locale_string, unsigned index) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->ShortMonthLabels()[index];
  }

  String ShortStandAloneMonthLabel(const char* locale_string, unsigned index) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->ShortStandAloneMonthLabels()[index];
  }

  String StandAloneMonthLabel(const char* locale_string, unsigned index) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->StandAloneMonthLabels()[index];
  }

  Labels TimeAMPMLabels(const char* locale_string) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return Labels(locale->TimeAMPMLabels());
  }

  bool IsRTL(const char* locale_string) {
    auto locale = std::make_unique<LocaleICU>(locale_string);
    return locale->IsRTL();
  }
};

std::ostream& operator<<(std::ostream& os,
                         const LocaleICUTest::Labels& labels) {
  return os << labels.ToString();
}

TEST_F(LocaleICUTest, isRTL) {
  EXPECT_TRUE(IsRTL("ar-EG"));
  EXPECT_FALSE(IsRTL("en-us"));
  EXPECT_FALSE(IsRTL("ja-jp"));
  EXPECT_FALSE(IsRTL("**invalid**"));
}

TEST_F(LocaleICUTest, monthFormat) {
  EXPECT_EQ("MMMM yyyy", MonthFormat("en_US"));
  EXPECT_EQ("MMMM yyyy", MonthFormat("fr"));
  EXPECT_EQ("yyyy\xE5\xB9\xB4M\xE6\x9C\x88", MonthFormat("ja").Utf8());
}

TEST_F(LocaleICUTest, localizedDateFormatText) {
  // Note: EXPECT_EQ(String, String) doesn't print result as string.
  EXPECT_EQ(
      "h:mm:ss\xE2\x80\xAF"
      "a",
      LocalizedDateFormatText("en_US").Utf8());
  EXPECT_EQ("HH:mm:ss", LocalizedDateFormatText("fr"));
  EXPECT_EQ("H:mm:ss", LocalizedDateFormatText("ja"));
}

TEST_F(LocaleICUTest, localizedShortDateFormatText) {
  EXPECT_EQ(
      "h:mm\xE2\x80\xAF"
      "a",
      LocalizedShortDateFormatText("en_US").Utf8());
  EXPECT_EQ("HH:mm", LocalizedShortDateFormatText("fr"));
  EXPECT_EQ("H:mm", LocalizedShortDateFormatText("ja"));
}

TEST_F(LocaleICUTest, standAloneMonthLabels) {
  EXPECT_EQ("January", StandAloneMonthLabel("en_US", 0));
  EXPECT_EQ("June", StandAloneMonthLabel("en_US", 5));
  EXPECT_EQ("December", StandAloneMonthLabel("en_US", 11));

#if U_ICU_VERSION_MAJOR_NUM >= 54
  EXPECT_EQ("Janvier", StandAloneMonthLabel("fr_FR", 0));
  EXPECT_EQ("Juin", StandAloneMonthLabel("fr_FR", 5));
  EXPECT_EQ(
      "D\xC3\xA9"
      "cembre",
      StandAloneMonthLabel("fr_FR", 11).Utf8());
#else
  EXPECT_EQ("janvier", standAloneMonthLabel("fr_FR", 0));
  EXPECT_EQ("juin", standAloneMonthLabel("fr_FR", 5));
  EXPECT_EQ(
      "d\xC3\xA9"
      "cembre",
      standAloneMonthLabel("fr_FR", 11));
#endif

  EXPECT_EQ("1\xE6\x9C\x88", StandAloneMonthLabel("ja_JP", 0).Utf8());
  EXPECT_EQ("6\xE6\x9C\x88", StandAloneMonthLabel("ja_JP", 5).Utf8());
  EXPECT_EQ("12\xE6\x9C\x88", StandAloneMonthLabel("ja_JP", 11).Utf8());

  EXPECT_EQ("\xD0\x9C\xD0\xB0\xD1\x80\xD1\x82",
            StandAloneMonthLabel("ru_RU", 2).Utf8());
  EXPECT_EQ("\xD0\x9C\xD0\xB0\xD0\xB9",
            StandAloneMonthLabel("ru_RU", 4).Utf8());
}

TEST_F(LocaleICUTest, shortMonthLabels) {
  EXPECT_EQ("Jan", ShortMonthLabel("en_US", 0));
  EXPECT_EQ("Jan", ShortStandAloneMonthLabel("en_US", 0));
  EXPECT_EQ("Dec", ShortMonthLabel("en_US", 11));
  EXPECT_EQ("Dec", ShortStandAloneMonthLabel("en_US", 11));

#if U_ICU_VERSION_MAJOR_NUM >= 54
  EXPECT_EQ("janv.", ShortMonthLabel("fr_FR", 0));
  EXPECT_EQ("Janv.", ShortStandAloneMonthLabel("fr_FR", 0));
  EXPECT_EQ(
      "d\xC3\xA9"
      "c.",
      ShortMonthLabel("fr_FR", 11).Utf8());
  EXPECT_EQ(
      "D\xC3\xA9"
      "c.",
      ShortStandAloneMonthLabel("fr_FR", 11).Utf8());
#else
  EXPECT_EQ("janv.", shortMonthLabel("fr_FR", 0));
  EXPECT_EQ("janv.", shortStandAloneMonthLabel("fr_FR", 0));
  EXPECT_EQ(
      "d\xC3\xA9"
      "c.",
      shortMonthLabel("fr_FR", 11));
  EXPECT_EQ(
      "d\xC3\xA9"
      "c.",
      shortStandAloneMonthLabel("fr_FR", 11));
#endif

  EXPECT_EQ("1\xE6\x9C\x88", ShortMonthLabel("ja_JP", 0).Utf8());
  EXPECT_EQ("1\xE6\x9C\x88", ShortStandAloneMonthLabel("ja_JP", 0).Utf8());
  EXPECT_EQ("12\xE6\x9C\x88", ShortMonthLabel("ja_JP", 11).Utf8());
  EXPECT_EQ("12\xE6\x9C\x88", ShortStandAloneMonthLabel("ja_JP", 11).Utf8());

  EXPECT_EQ("\xD0\xBC\xD0\xB0\xD1\x80.", ShortMonthLabel("ru_RU", 2).Utf8());
  EXPECT_EQ("\xD0\x9C\xD0\xB0\xD1\x80\xD1\x82",
            ShortStandAloneMonthLabel("ru_RU", 2).Utf8());
  EXPECT_EQ("\xD0\xBC\xD0\xB0\xD1\x8F", ShortMonthLabel("ru_RU", 4).Utf8());
  EXPECT_EQ("\xD0\x9C\xD0\xB0\xD0\xB9",
            ShortStandAloneMonthLabel("ru_RU", 4).Utf8());
}

TEST_F(LocaleICUTest, timeAMPMLabels) {
  EXPECT_EQ(LabelsFromTwoElements("AM", "PM"), TimeAMPMLabels("en_US"));
  EXPECT_EQ(LabelsFromTwoElements("AM", "PM"), TimeAMPMLabels("fr"));

  UChar ja_am[3] = {0x5348, 0x524d, 0};
  UChar ja_pm[3] = {0x5348, 0x5F8C, 0};
  EXPECT_EQ(LabelsFromTwoElements(String(ja_am), String(ja_pm)),
            TimeAMPMLabels("ja"));
}

static String TestDecimalSeparator(const AtomicString& locale_identifier) {
  std::unique_ptr<Locale> locale = Locale::Create(locale_identifier);
  return locale->LocalizedDecimalSeparator();
}

TEST_F(LocaleICUTest, localizedDecimalSeparator) {
  EXPECT_EQ(String("."), TestDecimalSeparator(AtomicString("en_US")));
  EXPECT_EQ(String(","), TestDecimalSeparator(AtomicString("fr")));
}

void TestNumberIsReversible(const AtomicString& locale_identifier,
                            const char* original,
                            const char* should_have = nullptr) {
  std::unique_ptr<Locale> locale = Locale::Create(locale_identifier);
  String localized = locale->ConvertToLocalizedNumber(original);
  if (should_have)
    EXPECT_TRUE(localized.Contains(should_have));
  String converted = locale->ConvertFromLocalizedNumber(localized);
  EXPECT_EQ(original, converted);
}

void TestNumbers(const char* locale) {
  AtomicString locale_string(locale);
  TestNumberIsReversible(locale_string, "123456789012345678901234567890");
  TestNumberIsReversible(locale_string, "-123.456");
  TestNumberIsReversible(locale_string, ".456");
  TestNumberIsReversible(locale_string, "-0.456");
}

TEST_F(LocaleICUTest, reversible) {
  AtomicString en_us_locale("en_US");
  TestNumberIsReversible(en_us_locale, "123456789012345678901234567890");
  TestNumberIsReversible(en_us_locale, "-123.456", ".");
  TestNumberIsReversible(en_us_locale, ".456", ".");
  TestNumberIsReversible(en_us_locale, "-0.456", ".");

  AtomicString fr_locale("fr");
  TestNumberIsReversible(fr_locale, "123456789012345678901234567890");
  TestNumberIsReversible(fr_locale, "-123.456", ",");
  TestNumberIsReversible(fr_locale, ".456", ",");
  TestNumberIsReversible(fr_locale, "-0.456", ",");

  // Persian locale has a negative prefix and a negative suffix.
  TestNumbers("fa");

  // Test some of major locales.
  TestNumbers("ar");
  TestNumbers("de_DE");
  TestNumbers("es_ES");
  TestNumbers("ja_JP");
  TestNumbers("ko_KR");
  TestNumbers("zh_CN");
  TestNumbers("zh_HK");
  TestNumbers("zh_TW");
}

}  // namespace blink
```
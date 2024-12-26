Response:
My thought process to answer the request about `locale_win_test.cc` goes like this:

1. **Understand the Goal:** The user wants to know the *functionality* of this C++ test file within the Chromium/Blink engine. Crucially, they're also asking about its relationship to web technologies (JavaScript, HTML, CSS), any logical inferences, and potential usage errors.

2. **Initial Scan for Keywords:** I quickly scan the code for obvious indicators:
    * `TEST_F`:  This confirms it's a test file using Google Test.
    * `LocaleWin`:  This is the core class being tested. The name suggests it deals with locale-specific information on Windows.
    * `FormatDate`, `FirstDayOfWeek`, `MonthLabel`, `WeekDayShortLabel`, `IsRTL`, `MonthFormat`, `TimeFormat`, `ShortTimeFormat`, `TimeAMPMLabel`, `DecimalSeparator`: These are methods of `LocaleWin` and clearly indicate its purpose: handling locale-specific formatting and information related to dates, times, numbers, and text direction.
    * `LCID`: This is a Windows-specific identifier for locales. The code defines several constants for different locales (e.g., `kEnglishUS`, `kFrenchFR`).
    * `EXPECT_EQ`:  This is a Google Test assertion, meaning the tests compare the *actual* output of `LocaleWin` methods with *expected* values.

3. **Inferring Core Functionality:** Based on the keywords and the structure of the tests, I can deduce the primary function: `locale_win_test.cc` tests the `LocaleWin` class, which is responsible for providing locale-sensitive formatting and information on Windows. This includes formatting dates, times, numbers, retrieving localized month and day names, determining the first day of the week, and checking text direction (RTL).

4. **Connecting to Web Technologies (HTML, CSS, JavaScript):**  This requires a bit more reasoning. While the C++ code doesn't directly manipulate HTML or CSS, it *supports* the rendering and behavior of web pages that *do*.

    * **JavaScript:**  JavaScript's `Intl` object provides similar locale-aware functionality. The `LocaleWin` class likely provides the underlying implementation for this functionality within the Blink rendering engine on Windows. When JavaScript code uses `Intl.DateTimeFormat`, for instance, Blink needs to get the appropriate formatting rules, and `LocaleWin` is a likely candidate for providing those rules on Windows.

    * **HTML:** HTML elements like `<input type="date">` and `<input type="time">` rely on the browser's locale settings for display and input parsing. `LocaleWin` would be involved in determining how these elements are rendered and how user input is interpreted on Windows. The `dir="rtl"` attribute also directly relates to the RTL functionality tested.

    * **CSS:** While CSS doesn't directly interact with date/time formatting, the `direction` property (for RTL languages) is influenced by locale. The `IsRTL()` function in `LocaleWin` would be relevant here.

5. **Developing Examples:** To illustrate the connection to web technologies, I need concrete examples:

    * **JavaScript:**  Show how `Intl.DateTimeFormat` produces different output based on the locale.
    * **HTML:** Demonstrate how the `<input type="date">` element's display changes with the locale.
    * **CSS:** Illustrate the effect of the `direction: rtl` property.

6. **Logical Inference (Assumptions and Outputs):** The tests themselves provide clear examples of input (LCID, date components) and expected output (formatted date string, day of the week, etc.). I can extract these examples and present them in a more structured way. The core logic being tested is the correct application of Windows locale settings.

7. **Common Usage Errors:**  This requires thinking about how developers might misuse locale-related functionality or encounter issues:

    * **Assuming a fixed format:** Developers might hardcode date formats instead of relying on locale settings, leading to incorrect display for users in other regions.
    * **Incorrect locale handling:**  Not setting or handling locale information correctly in JavaScript or server-side code.
    * **RTL issues:**  Forgetting to handle right-to-left layouts, leading to text overlapping or misalignment.
    * **Number formatting:**  Not being aware of different decimal and thousands separators.

8. **Structuring the Answer:** Finally, I organize the information into logical sections (Functionality, Relationship to Web Technologies, Logical Inference, Common Usage Errors) with clear headings and explanations. I use code blocks to present the examples effectively. I also ensure the language is clear and concise.

By following these steps, I can create a comprehensive and accurate answer that addresses all aspects of the user's request, going beyond simply stating the file's purpose and delving into its broader context and implications.
这个文件 `locale_win_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是 **测试 `LocaleWin` 类在 Windows 平台上的本地化功能**。

`LocaleWin` 类负责处理与特定语言和文化区域设置（即“locale”）相关的操作，例如日期、时间、数字和货币的格式化，以及获取本地化的月份和星期几名称等。 由于这些本地化规则在不同的操作系统和平台上可能有所不同，因此需要针对特定平台（如 Windows）进行测试。

**具体功能点如下：**

1. **日期格式化测试 (`formatDate` 测试用例):**
   - 测试 `LocaleWin::FormatDateTime` 方法是否能根据给定的 LCID (Locale Identifier，Windows 中表示 locale 的方式) 正确格式化日期。
   - **例子:** 使用不同的 LCID (如 `kEnglishUS`, `kFrenchFR`, `kJapaneseJP`) 和相同的日期 (2005年4月27日)，断言输出的日期字符串是否符合该 locale 的习惯。
   - **与 JavaScript, HTML, CSS 的关系:**  当 JavaScript 代码使用 `Intl.DateTimeFormat()` 进行日期格式化时，Blink 引擎在 Windows 平台上可能会使用 `LocaleWin` 类来获取相应的格式化规则。HTML 的 `<input type="date">` 元素的显示格式也可能受到这些本地化设置的影响。CSS 本身不直接参与日期格式化，但可能影响包含日期文本的元素的布局。

2. **一周的第一天测试 (`firstDayOfWeek` 测试用例):**
   - 测试 `LocaleWin::FirstDayOfWeek` 方法是否能正确返回指定 locale 的一周的第一天 (例如，美国是星期日，法国是星期一)。
   - **例子:** 使用不同的 LCID 并断言返回的星期几枚举值是否正确。
   - **与 JavaScript, HTML, CSS 的关系:**  JavaScript 的 `Intl.DateTimeFormat()` 可以获取一周的第一天。在 HTML 中，一些日期选择器控件可能会根据 locale 设置来决定日历的起始列。CSS 不直接相关。

3. **月份标签测试 (`monthLabels` 测试用例):**
   - 测试 `LocaleWin::MonthLabels` 方法是否能正确返回指定 locale 的完整月份名称。
   - **例子:** 使用不同的 LCID 并断言返回的月份名称字符串是否正确，包括处理 Unicode 字符的情况。
   - **与 JavaScript, HTML, CSS 的关系:** JavaScript 的 `Intl.DateTimeFormat()` 可以获取本地化的月份名称。在 HTML 中，一些动态生成的日历或日期显示可能会使用这些本地化的月份名称。CSS 可以用来设置这些月份名称的样式。

4. **短星期几标签测试 (`weekDayShortLabels` 测试用例):**
   - 测试 `LocaleWin::WeekDayShortLabels` 方法是否能正确返回指定 locale 的短星期几名称。
   - **例子:** 使用不同的 LCID 并断言返回的短星期几名称字符串是否正确。
   - **与 JavaScript, HTML, CSS 的关系:** 与月份标签类似，JavaScript 的 `Intl.DateTimeFormat()` 可以获取本地化的短星期几名称，HTML 和 CSS 也可能用于显示和样式化这些名称。

5. **RTL (Right-to-Left) 语言测试 (`isRTL` 测试用例):**
   - 测试 `LocaleWin::IsRTL` 方法是否能正确判断指定 locale 的文本方向是否为从右到左。
   - **例子:** 使用阿拉伯语 (kArabicEG) 和英语 (kEnglishUS) 的 LCID 并断言返回值是否正确。
   - **与 JavaScript, HTML, CSS 的关系:**  HTML 的 `dir` 属性（如 `<html dir="rtl">`）和 CSS 的 `direction` 属性用于指定文本方向。`LocaleWin::IsRTL` 的结果可能会影响 Blink 引擎在渲染网页时如何处理文本布局。JavaScript 可以读取这些属性，并根据 locale 进行调整。

6. **日期格式模式测试 (`dateFormat` 测试用例):**
   - 测试 `LocaleWin::DateFormat` 方法是否能正确处理日期格式字符串中的引号，这对于构建复杂的日期格式很有用。
   - **假设输入:** 各种包含单引号的日期格式字符串，例如 `"y-M-d"`, `"''yy'-'''MM'''-'dd"`, 等等。
   - **预期输出:**  经过处理后的日期格式字符串。这个测试更侧重于 `LocaleWin` 内部的字符串处理逻辑，不直接与特定 locale 相关。
   - **与 JavaScript, HTML, CSS 的关系:**  当需要自定义日期格式时，这些模式可能会被 JavaScript 的 `Intl.DateTimeFormat()` 构造函数使用。HTML 和 CSS 不直接相关。

7. **月份格式测试 (`monthFormat` 测试用例):**
   - 测试 `LocaleWin::MonthFormat` 方法是否能正确返回指定 locale 的月份格式字符串。
   - **例子:** 使用不同的 LCID 并断言返回的月份格式字符串是否符合该 locale 的习惯。
   - **与 JavaScript, HTML, CSS 的关系:** 与日期格式化类似，JavaScript 可以使用这些格式来显示月份和年份。

8. **时间格式测试 (`timeFormat`, `shortTimeFormat` 测试用例):**
   - 测试 `LocaleWin::TimeFormat` 和 `LocaleWin::ShortTimeFormat` 方法是否能正确返回指定 locale 的完整和简短时间格式字符串。
   - **例子:** 使用不同的 LCID 并断言返回的时间格式字符串是否符合该 locale 的习惯 (例如，12 小时制 vs. 24 小时制)。
   - **与 JavaScript, HTML, CSS 的关系:** JavaScript 的 `Intl.DateTimeFormat()` 可以使用这些格式来显示时间。HTML 的 `<input type="time">` 元素的显示格式也会受到影响。

9. **AM/PM 标签测试 (`timeAMPMLabels` 测试用例):**
   - 测试 `LocaleWin::TimeAMPMLabels` 方法是否能正确返回指定 locale 的 AM 和 PM 标签。
   - **例子:** 使用不同的 LCID 并断言返回的 AM/PM 标签字符串是否正确 (有些 locale 可能没有 AM/PM)。
   - **与 JavaScript, HTML, CSS 的关系:**  当 JavaScript 需要显示 12 小时制时间时，会用到这些标签。

10. **小数分隔符测试 (`decimalSeparator` 测试用例):**
    - 测试 `LocaleWin::LocalizedDecimalSeparator` 方法是否能正确返回指定 locale 的小数分隔符 (例如，英文是 "."，法语是 ",")。
    - **例子:** 使用不同的 LCID 并断言返回的小数分隔符字符串是否正确。
    - **与 JavaScript, HTML, CSS 的关系:**  当 JavaScript 需要格式化或解析数字时，会用到小数分隔符。HTML 表单中输入的数字也会根据 locale 设置进行解析。CSS 本身不直接相关。

11. **本地化数字的往返测试 (`localizedNumberRoundTrip` 测试用例):**
    - 测试 `LocaleWin::ConvertToLocalizedNumber` 和 `LocaleWin::ConvertFromLocalizedNumber` 方法是否能正确地将标准数字字符串转换为本地化格式，然后再转换回标准格式，确保数据没有丢失。
    - **假设输入:** 不同格式的数字字符串，包括整数、小数、负数。
    - **预期输出:**  转换后的本地化数字字符串，以及再转换回来的原始数字字符串。
    - **例子:** 测试不同 locale 下数字的本地化和反本地化，包括包含小数分隔符的情况。
    - **与 JavaScript, HTML, CSS 的关系:**  当需要在网页上显示本地化格式的数字时，这些方法的功能至关重要。例如，显示价格、统计数据等。JavaScript 的 `Intl.NumberFormat()` 提供了类似的功能。

**逻辑推理的例子:**

* **假设输入 (针对 `formatDate`):**
    * `lcid = kFrenchFR` (法国 locale)
    * `year = 2023`
    * `month = kDecember` (12月)
    * `day = 25`
* **预期输出:** `"25/12/2023"` (因为法国的日期格式通常是 日/月/年)

**用户或编程常见的使用错误举例:**

1. **硬编码日期/时间格式:** 开发者可能直接在代码中使用固定的日期/时间格式字符串 (例如 `"YYYY-MM-DD"`)，而不是依赖用户的 locale 设置。这会导致应用在不同地区显示不一致的格式，影响用户体验。

   ```javascript
   // 错误的做法：硬编码日期格式
   const date = new Date();
   const formattedDate = `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
   ```

   **正确的做法:** 使用 `Intl.DateTimeFormat()` 根据用户的 locale 进行格式化。

   ```javascript
   const date = new Date();
   const formattedDate = new Intl.DateTimeFormat().format(date);
   ```

2. **错误地假设小数分隔符:**  开发者可能会假设所有地区都使用 "." 作为小数分隔符，在处理用户输入或显示数字时出错。

   ```javascript
   // 错误的做法：假设使用 "." 作为小数分隔符
   const priceString = "123.45";
   const price = parseFloat(priceString); // 在某些 locale 下可能会解析失败
   ```

   **正确的做法:** 使用 `Intl.NumberFormat()` 进行格式化和解析，或者在解析用户输入时考虑到不同的分隔符。

3. **忽略 RTL 语言的支持:**  在设计用户界面时，没有考虑到从右到左的语言，导致文本布局错乱，影响阿拉伯语、希伯来语等用户的体验。

   ```html
   <!-- 没有考虑 RTL -->
   <div>This is some text.</div>

   <!-- 考虑 RTL -->
   <div dir="auto">هذا بعض النصوص.</div>
   ```

总而言之，`locale_win_test.cc` 这个文件通过一系列单元测试，确保了 `LocaleWin` 类在 Windows 平台上能够正确地处理各种本地化相关的任务，这对于构建能够适应不同语言和文化用户的 Web 应用程序至关重要。它直接支持了浏览器在处理 JavaScript 的国际化 API 和渲染本地化内容时的正确性。

Prompt: 
```
这是目录为blink/renderer/platform/text/locale_win_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#include "third_party/blink/renderer/platform/text/locale_win.h"

#include <memory>
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/base/ui_base_features.h"

namespace blink {

class LocaleWinTest : public testing::Test {
 protected:
  enum {
    kJanuary = 0,
    kFebruary,
    kMarch,
    kApril,
    kMay,
    kJune,
    kJuly,
    kAugust,
    kSeptember,
    kOctober,
    kNovember,
    kDecember,
  };

  enum {
    kSunday = 0,
    kMonday,
    kTuesday,
    kWednesday,
    kThursday,
    kFriday,
    kSaturday,
  };

  // See http://msdn.microsoft.com/en-us/goglobal/bb964664.aspx
  // Note that some locales are country-neutral.
  enum {
    kArabicEG = 0x0C01,   // ar-eg
    kChineseCN = 0x0804,  // zh-cn
    kChineseHK = 0x0C04,  // zh-hk
    kChineseTW = 0x0404,  // zh-tw
    kGerman = 0x0407,     // de
    kEnglishUS = 0x409,   // en-us
    kFrenchFR = 0x40C,    // fr
    kJapaneseJP = 0x411,  // ja
    kKoreanKR = 0x0412,   // ko
    kPersian = 0x0429,    // fa
    kSpanish = 0x040A,    // es
  };

  DateComponents GetDateComponents(int year, int month, int day) {
    DateComponents date;
    date.SetMillisecondsSinceEpochForDate(MsForDate(year, month, day));
    return date;
  }

  double MsForDate(int year, int month, int day) {
    return DateToDaysFrom1970(year, month, day) * kMsPerDay;
  }

  String FormatDate(LCID lcid, int year, int month, int day) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->FormatDateTime(GetDateComponents(year, month, day));
  }

  unsigned FirstDayOfWeek(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->FirstDayOfWeek();
  }

  String MonthLabel(LCID lcid, unsigned index) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->MonthLabels()[index];
  }

  String WeekDayShortLabel(LCID lcid, unsigned index) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->WeekDayShortLabels()[index];
  }

  bool IsRTL(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->IsRTL();
  }

  String MonthFormat(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->MonthFormat();
  }

  String TimeFormat(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->TimeFormat();
  }

  String ShortTimeFormat(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->ShortTimeFormat();
  }

  String ShortMonthLabel(LCID lcid, unsigned index) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->ShortMonthLabels()[index];
  }

  String TimeAMPMLabel(LCID lcid, unsigned index) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->TimeAMPMLabels()[index];
  }

  String DecimalSeparator(LCID lcid) {
    std::unique_ptr<LocaleWin> locale =
        LocaleWin::Create(lcid, true /* defaultsForLocale */);
    return locale->LocalizedDecimalSeparator();
  }
};

TEST_F(LocaleWinTest, formatDate) {
  EXPECT_EQ("04/27/2005", FormatDate(kEnglishUS, 2005, kApril, 27));
  EXPECT_EQ("27/04/2005", FormatDate(kFrenchFR, 2005, kApril, 27));
  EXPECT_EQ("2005/04/27", FormatDate(kJapaneseJP, 2005, kApril, 27));
}

TEST_F(LocaleWinTest, firstDayOfWeek) {
  EXPECT_EQ(static_cast<unsigned>(kSunday), FirstDayOfWeek(kEnglishUS));
  EXPECT_EQ(static_cast<unsigned>(kMonday), FirstDayOfWeek(kFrenchFR));
  EXPECT_EQ(static_cast<unsigned>(kSunday), FirstDayOfWeek(kJapaneseJP));
}

TEST_F(LocaleWinTest, monthLabels) {
  EXPECT_EQ("January", MonthLabel(kEnglishUS, kJanuary));
  EXPECT_EQ("June", MonthLabel(kEnglishUS, kJune));
  EXPECT_EQ("December", MonthLabel(kEnglishUS, kDecember));

  EXPECT_EQ("janvier", MonthLabel(kFrenchFR, kJanuary));
  EXPECT_EQ("juin", MonthLabel(kFrenchFR, kJune));
  EXPECT_EQ(
      "d\xC3\xA9"
      "cembre",
      MonthLabel(kFrenchFR, kDecember).Utf8());

  EXPECT_EQ("1\xE6\x9C\x88", MonthLabel(kJapaneseJP, kJanuary).Utf8());
  EXPECT_EQ("6\xE6\x9C\x88", MonthLabel(kJapaneseJP, kJune).Utf8());
  EXPECT_EQ("12\xE6\x9C\x88", MonthLabel(kJapaneseJP, kDecember).Utf8());
}

TEST_F(LocaleWinTest, weekDayShortLabels) {
  EXPECT_EQ("Su", WeekDayShortLabel(kEnglishUS, kSunday));
  EXPECT_EQ("We", WeekDayShortLabel(kEnglishUS, kWednesday));
  EXPECT_EQ("Sa", WeekDayShortLabel(kEnglishUS, kSaturday));

  EXPECT_EQ("di", WeekDayShortLabel(kFrenchFR, kSunday));
  EXPECT_EQ("me", WeekDayShortLabel(kFrenchFR, kWednesday));
  EXPECT_EQ("sa", WeekDayShortLabel(kFrenchFR, kSaturday));
  EXPECT_EQ("\xE6\x97\xA5", WeekDayShortLabel(kJapaneseJP, kSunday).Utf8());
  EXPECT_EQ("\xE6\xB0\xB4", WeekDayShortLabel(kJapaneseJP, kWednesday).Utf8());
  EXPECT_EQ("\xE5\x9C\x9F", WeekDayShortLabel(kJapaneseJP, kSaturday).Utf8());
}

TEST_F(LocaleWinTest, isRTL) {
  EXPECT_TRUE(IsRTL(kArabicEG));
  EXPECT_FALSE(IsRTL(kEnglishUS));
}

TEST_F(LocaleWinTest, dateFormat) {
  EXPECT_EQ("y-M-d", LocaleWin::DateFormat("y-M-d"));
  EXPECT_EQ("''yy'-'''MM'''-'dd", LocaleWin::DateFormat("''yy-''MM''-dd"));
  EXPECT_EQ("yyyy'-''''-'MMM'''''-'dd",
            LocaleWin::DateFormat("yyyy-''''-MMM''''-dd"));
  EXPECT_EQ("yyyy'-'''''MMMM-dd", LocaleWin::DateFormat("yyyy-''''MMMM-dd"));
}

TEST_F(LocaleWinTest, monthFormat) {
  // Month format for EnglishUS:
  //  "MMMM, yyyy" on Windows 7 or older.
  //  "MMMM yyyy" on Window 8 or later.
  EXPECT_EQ("MMMM yyyy", MonthFormat(kEnglishUS).Replace(',', ""));
  EXPECT_EQ("MMMM yyyy", MonthFormat(kFrenchFR));
  EXPECT_EQ("yyyy\xE5\xB9\xB4M\xE6\x9C\x88", MonthFormat(kJapaneseJP).Utf8());
}

TEST_F(LocaleWinTest, timeFormat) {
  EXPECT_EQ("h:mm:ss a", TimeFormat(kEnglishUS));
  EXPECT_EQ("HH:mm:ss", TimeFormat(kFrenchFR));
  EXPECT_EQ("H:mm:ss", TimeFormat(kJapaneseJP));
}

TEST_F(LocaleWinTest, shortTimeFormat) {
  EXPECT_EQ("h:mm a", ShortTimeFormat(kEnglishUS));
  EXPECT_EQ("HH:mm", ShortTimeFormat(kFrenchFR));
  EXPECT_EQ("H:mm", ShortTimeFormat(kJapaneseJP));
}

TEST_F(LocaleWinTest, shortMonthLabels) {
  EXPECT_EQ("Jan", ShortMonthLabel(kEnglishUS, 0));
  EXPECT_EQ("Dec", ShortMonthLabel(kEnglishUS, 11));
  EXPECT_EQ("janv.", ShortMonthLabel(kFrenchFR, 0));
  EXPECT_EQ(
      "d\xC3\xA9"
      "c.",
      ShortMonthLabel(kFrenchFR, 11).Utf8());
  EXPECT_EQ("1", ShortMonthLabel(kJapaneseJP, 0));
  EXPECT_EQ("12", ShortMonthLabel(kJapaneseJP, 11));
}

TEST_F(LocaleWinTest, timeAMPMLabels) {
  EXPECT_EQ("AM", TimeAMPMLabel(kEnglishUS, 0));
  EXPECT_EQ("PM", TimeAMPMLabel(kEnglishUS, 1));

  EXPECT_EQ("", TimeAMPMLabel(kFrenchFR, 0).Utf8());
  EXPECT_EQ("", TimeAMPMLabel(kFrenchFR, 1).Utf8());

  EXPECT_EQ("\xE5\x8D\x88\xE5\x89\x8D", TimeAMPMLabel(kJapaneseJP, 0).Utf8());
  EXPECT_EQ("\xE5\x8D\x88\xE5\xBE\x8C", TimeAMPMLabel(kJapaneseJP, 1).Utf8());
}

TEST_F(LocaleWinTest, decimalSeparator) {
  EXPECT_EQ(".", DecimalSeparator(kEnglishUS));
  EXPECT_EQ(",", DecimalSeparator(kFrenchFR));
}

static void TestNumberIsReversible(LCID lcid,
                                   const char* original,
                                   const char* should_have = 0) {
  std::unique_ptr<LocaleWin> locale =
      LocaleWin::Create(lcid, true /* defaultsForLocale */);
  String localized = locale->ConvertToLocalizedNumber(original);
  if (should_have)
    EXPECT_TRUE(localized.Contains(should_have));
  String converted = locale->ConvertFromLocalizedNumber(localized);
  EXPECT_EQ(original, converted);
}

void TestNumbers(LCID lcid) {
  TestNumberIsReversible(lcid, "123456789012345678901234567890");
  TestNumberIsReversible(lcid, "-123.456");
  TestNumberIsReversible(lcid, ".456");
  TestNumberIsReversible(lcid, "-0.456");
}

TEST_F(LocaleWinTest, localizedNumberRoundTrip) {
  TestNumberIsReversible(kEnglishUS, "123456789012345678901234567890");
  TestNumberIsReversible(kEnglishUS, "-123.456", ".");
  TestNumberIsReversible(kEnglishUS, ".456", ".");
  TestNumberIsReversible(kEnglishUS, "-0.456", ".");

  TestNumberIsReversible(kFrenchFR, "123456789012345678901234567890");
  TestNumberIsReversible(kFrenchFR, "-123.456", ",");
  TestNumberIsReversible(kFrenchFR, ".456", ",");
  TestNumberIsReversible(kFrenchFR, "-0.456", ",");

  // Test some of major locales.
  TestNumbers(kArabicEG);
  TestNumbers(kGerman);
  TestNumbers(kSpanish);
  TestNumbers(kPersian);
  TestNumbers(kJapaneseJP);
  TestNumbers(kKoreanKR);
  TestNumbers(kChineseCN);
  TestNumbers(kChineseHK);
  TestNumbers(kChineseTW);
}

}  // namespace blink

"""

```